defmodule ClerkPhoenix.TokenBlacklist do
  @moduledoc """
  Token blacklist management for revoked JWT tokens.

  Provides functionality to:
  - Add tokens to blacklist when they are revoked
  - Check if tokens are blacklisted
  - Clean up expired blacklist entries
  - Persist blacklist across application restarts
  """

  use GenServer
  require Logger

  @blacklist_table :clerk_token_blacklist
  @cleanup_interval 60 * 60 * 1000  # 1 hour in milliseconds

  ## Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Adds a token to the blacklist.

  ## Parameters
  - `jti` - The JWT ID (jti claim) of the token to blacklist
  - `exp` - The expiration timestamp of the token (optional)

  ## Examples

      iex> ClerkPhoenix.TokenBlacklist.blacklist_token("token_123", 1234567890)
      :ok
  """
  def blacklist_token(jti, exp \\ nil) when is_binary(jti) do
    GenServer.cast(__MODULE__, {:blacklist_token, jti, exp})
  end

  @doc """
  Checks if a token is blacklisted.

  ## Parameters
  - `jti` - The JWT ID (jti claim) to check

  ## Returns
  - `true` if the token is blacklisted
  - `false` if the token is not blacklisted

  ## Examples

      iex> ClerkPhoenix.TokenBlacklist.blacklisted?("token_123")
      true

      iex> ClerkPhoenix.TokenBlacklist.blacklisted?("valid_token")
      false
  """
  def blacklisted?(jti) when is_binary(jti) do
    case :ets.lookup(@blacklist_table, jti) do
      [{^jti, _exp, _blacklisted_at}] -> true
      [] -> false
    end
  rescue
    ArgumentError ->
      # Table doesn't exist yet
      false
  end

  def blacklisted?(_), do: false

  @doc """
  Removes a token from the blacklist.

  This is typically not needed since tokens expire naturally,
  but can be useful for testing or administrative purposes.

  ## Parameters
  - `jti` - The JWT ID to remove from blacklist

  ## Examples

      iex> ClerkPhoenix.TokenBlacklist.remove_from_blacklist("token_123")
      :ok
  """
  def remove_from_blacklist(jti) when is_binary(jti) do
    GenServer.cast(__MODULE__, {:remove_from_blacklist, jti})
  end

  @doc """
  Gets the current size of the blacklist.

  ## Examples

      iex> ClerkPhoenix.TokenBlacklist.size()
      42
  """
  def size do
    GenServer.call(__MODULE__, :size)
  end

  @doc """
  Gets statistics about the blacklist.

  ## Examples

      iex> ClerkPhoenix.TokenBlacklist.stats()
      %{
        total_blacklisted: 42,
        expired_entries: 5,
        active_entries: 37,
        oldest_entry: ~U[2023-01-01 00:00:00Z],
        newest_entry: ~U[2023-12-31 23:59:59Z]
      }
  """
  def stats do
    GenServer.call(__MODULE__, :stats)
  end

  @doc """
  Manually triggers cleanup of expired blacklist entries.

  This is automatically done periodically, but can be triggered manually.

  ## Examples

      iex> ClerkPhoenix.TokenBlacklist.cleanup()
      :ok
  """
  def cleanup do
    GenServer.cast(__MODULE__, :cleanup)
  end

  ## GenServer Callbacks

  @impl true
  def init(_opts) do
    # Create ETS table for blacklist
    table = :ets.new(@blacklist_table, [
      :named_table,
      :public,
      :set,
      read_concurrency: true,
      write_concurrency: true
    ])

    # Schedule periodic cleanup
    schedule_cleanup()

    Logger.info("ClerkPhoenix TokenBlacklist started")

    {:ok, %{table: table}}
  end

  @impl true
  def handle_cast({:blacklist_token, jti, exp}, state) do
    blacklisted_at = System.system_time(:second)

    # Store with expiration time if provided, otherwise use a default long expiration
    expiration = exp || (blacklisted_at + 24 * 60 * 60)  # 24 hours default

    :ets.insert(@blacklist_table, {jti, expiration, blacklisted_at})

    Logger.debug("Token blacklisted", jti: jti, exp: expiration)

    {:noreply, state}
  end

  @impl true
  def handle_cast({:remove_from_blacklist, jti}, state) do
    :ets.delete(@blacklist_table, jti)

    Logger.debug("Token removed from blacklist", jti: jti)

    {:noreply, state}
  end

  @impl true
  def handle_cast(:cleanup, state) do
    cleanup_expired_tokens()
    {:noreply, state}
  end

  @impl true
  def handle_cast(:clear_all, state) do
    :ets.delete_all_objects(@blacklist_table)
    Logger.warning("All blacklisted tokens cleared")
    {:noreply, state}
  end

  @impl true
  def handle_call(:size, _from, state) do
    size = :ets.info(@blacklist_table, :size)
    {:reply, size, state}
  end

  @impl true
  def handle_call(:stats, _from, state) do
    stats = calculate_stats()
    {:reply, stats, state}
  end

  @impl true
  def handle_call(:list_all, _from, state) do
    all_entries = :ets.tab2list(@blacklist_table)
    {:reply, all_entries, state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    cleanup_expired_tokens()
    schedule_cleanup()
    {:noreply, state}
  end

  # Private functions

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval)
  end

  defp cleanup_expired_tokens do
    current_time = System.system_time(:second)

    # Find and delete expired tokens
    expired_count = :ets.select_delete(@blacklist_table, [
      {{:"$1", :"$2", :"$3"},
       [{:<, :"$2", current_time}],
       [true]}
    ])

    if expired_count > 0 do
      Logger.debug("Cleaned up expired blacklisted tokens", count: expired_count)
    end

    expired_count
  end

  defp calculate_stats do
    current_time = System.system_time(:second)

    all_entries = :ets.tab2list(@blacklist_table)
    total_count = length(all_entries)

    if total_count == 0 do
      %{
        total_blacklisted: 0,
        expired_entries: 0,
        active_entries: 0,
        oldest_entry: nil,
        newest_entry: nil
      }
    else
      {expired_count, active_count, oldest_timestamp, newest_timestamp} =
        Enum.reduce(all_entries, {0, 0, nil, nil}, fn {_jti, exp, blacklisted_at}, {exp_acc, act_acc, old_acc, new_acc} ->
          is_expired = exp < current_time
          exp_count = if is_expired, do: exp_acc + 1, else: exp_acc
          act_count = if is_expired, do: act_acc, else: act_acc + 1

          oldest = case old_acc do
            nil -> blacklisted_at
            old when blacklisted_at < old -> blacklisted_at
            old -> old
          end

          newest = case new_acc do
            nil -> blacklisted_at
            new when blacklisted_at > new -> blacklisted_at
            new -> new
          end

          {exp_count, act_count, oldest, newest}
        end)

      %{
        total_blacklisted: total_count,
        expired_entries: expired_count,
        active_entries: active_count,
        oldest_entry: if(oldest_timestamp, do: DateTime.from_unix!(oldest_timestamp)),
        newest_entry: if(newest_timestamp, do: DateTime.from_unix!(newest_timestamp))
      }
    end
  end

  ## Utility functions for integration with JWT validation

  @doc """
  Extracts JTI from JWT claims and checks blacklist.

  This is a convenience function for use in JWT validation pipelines.

  ## Parameters
  - `claims` - JWT claims map

  ## Returns
  - `:ok` if token is not blacklisted
  - `{:error, :token_blacklisted}` if token is blacklisted

  ## Examples

      iex> ClerkPhoenix.TokenBlacklist.check_claims(%{"jti" => "token_123"})
      {:error, :token_blacklisted}

      iex> ClerkPhoenix.TokenBlacklist.check_claims(%{"jti" => "valid_token"})
      :ok
  """
  def check_claims(%{"jti" => jti}) when is_binary(jti) do
    if blacklisted?(jti) do
      {:error, :token_blacklisted}
    else
      :ok
    end
  end

  def check_claims(_claims), do: :ok  # No JTI claim, can't check blacklist

  @doc """
  Blacklists a token based on its JWT claims.

  This extracts the JTI and expiration from the claims and adds to blacklist.

  ## Parameters
  - `claims` - JWT claims map

  ## Examples

      iex> ClerkPhoenix.TokenBlacklist.blacklist_from_claims(%{"jti" => "token_123", "exp" => 1234567890})
      :ok
  """
  def blacklist_from_claims(%{"jti" => jti} = claims) when is_binary(jti) do
    exp = Map.get(claims, "exp")
    blacklist_token(jti, exp)
  end

  def blacklist_from_claims(_claims) do
    Logger.warning("Attempted to blacklist token without JTI claim")
    {:error, :no_jti_claim}
  end

  ## Administrative functions

  @doc """
  Clears all entries from the blacklist.

  This is primarily for testing and administrative purposes.
  Use with caution in production.

  ## Examples

      iex> ClerkPhoenix.TokenBlacklist.clear_all()
      :ok
  """
  def clear_all do
    GenServer.cast(__MODULE__, :clear_all)
  end

  @doc """
  Lists all blacklisted tokens (for debugging/admin purposes).

  Returns a list of tuples with {jti, expiration, blacklisted_at}.
  Use with caution as this can be memory intensive for large blacklists.

  ## Examples

      iex> ClerkPhoenix.TokenBlacklist.list_all()
      [
        {"token_123", 1234567890, 1234567800},
        {"token_456", 1234567900, 1234567850}
      ]
  """
  def list_all do
    GenServer.call(__MODULE__, :list_all)
  end
end
