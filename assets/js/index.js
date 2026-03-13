import { ClerkAuth } from "./hooks/clerk-auth-hook";
import { ClerkSignOut } from "./hooks/clerk-sign-out-hook";
import { ClerkSessionMonitor } from "./hooks/clerk-session-monitor-hook";

export { ClerkAuth, ClerkSignOut, ClerkSessionMonitor };
export const hooks = { ClerkAuth, ClerkSignOut, ClerkSessionMonitor };
