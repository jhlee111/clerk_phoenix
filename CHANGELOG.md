# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.4] - 2025-06-19

### Added
- **LiveView Session Support**: Added session storage for authentication data to enable LiveView access
- **LiveView Helper Module**: New `ClerkPhoenix.LiveView` module with authentication helpers for LiveView mounts
- **Enhanced Session Management**: Store minimal auth data in session for cross-request access

### Changed
- **AuthPlug Enhancement**: Modified `ClerkPhoenix.Plug.AuthPlug` to store authentication data in session
- **FrontendConfigPlug Enhancement**: Added session storage for Clerk configuration data
- **Session Data Management**: Added proper cleanup of LiveView session data on sign-out

### Fixed
- **LiveView Authentication**: LiveView components can now access authentication state through session data
- **Session Cleanup**: Proper clearing of session data when authentication fails or user signs out

### Technical Details
- Added `store_auth_data_for_liveview/3` function to store minimal identity and auth context in session
- Added `clear_liveview_session_data/1` function for proper session cleanup
- Modified authentication flow to support both connection assigns and session storage
- Enhanced frontend config plug to store configuration in session for LiveView access

## [0.1.3] - 2025-06-19

### Added
- **Frontend Configuration Plug**: New `ClerkPhoenix.Plug.FrontendConfigPlug` for complete frontend integration
- **Template Integration**: Seamless integration with Phoenix templates via `@clerk_config` assign
- **JavaScript SDK Configuration**: Automatic configuration for Clerk JavaScript SDK in templates

### Enhanced
- **Router Pipeline Integration**: Simplified setup with dedicated frontend config plug
- **Template Access**: Direct access to Clerk configuration in all templates and LiveViews
- **Documentation**: Updated README with comprehensive frontend integration examples

## [0.1.2] - 2025-06-17

### Removed
- **Obsolete Dependencies**: Removed Jason dependency since JSON is now built into Elixir
- **Obsolete Middleware**: Removed AuthPipeline middleware with references to deleted RBAC/Security modules
- **Documentation Cleanup**: Removed references to deleted Security.Monitor and other removed modules

### Changed
- **JSON Handling**: Modernized to use built-in JSON module instead of Jason
- **README**: Comprehensive update with working examples based on clerk_demo implementation
- **Documentation**: Updated module documentation groups to reflect current architecture
- **Template Syntax**: Fixed examples to use .heex instead of .eex

### Fixed
- **Tests**: Updated to use correct function names and proper assertions
- **Compiler Warnings**: Removed unused variables and obsolete references
- **Version Numbers**: Updated examples to reflect current 0.1.x series

## [0.1.1] - 2024-06-16

### Fixed
- **Optional Auth Redirect Loop**: Fixed infinite redirect loop in optional authentication mode when JWT sessions expire
- Optional auth now clears expired sessions silently and continues unauthenticated instead of redirecting to sign-in
- Preserves Clerk's development flow using `__session` cookie for cross-origin authentication
- Updated README with correct plug syntax examples

### Technical Details
- Modified `ClerkPhoenix.Plug.AuthPlug` to handle `:session_expired` correctly in optional auth mode
- Added tests to verify optional auth behavior never redirects
- Fixed documentation examples showing incorrect `plug/3` syntax

## [0.1.0] - 2024-06-16

### Added
- Core authentication functionality with Clerk integration
- JWT token validation and identity extraction
- Session management with security features
- Phoenix plug for authentication (`ClerkPhoenix.Plug.AuthPlug`)
- Identity mapping configuration for flexible claim extraction
- Authentication context management
- Session security hardening (fingerprinting, rotation, validation)
- Token blacklisting support
- Configuration management with sensible defaults

### Architecture
- **Authentication-focused design**: ClerkPhoenix handles authentication only, not user management
- **Clean separation of concerns**: Applications handle user models and business logic
- **Phoenix integration**: Seamless integration with Phoenix pipelines and plugs
- **Security-first approach**: Built-in session security and token validation

### Documentation
- Comprehensive README with setup and usage examples
- Clear migration guide for architectural decisions
- Examples for Phoenix router setup and controller usage
- Documentation for all configuration options

### Testing
- Interface-focused test suite
- Tests for core authentication functionality
- Configuration and plug testing

This initial release establishes ClerkPhoenix as a focused authentication library that integrates with Clerk while maintaining clean architectural boundaries between authentication and user management concerns.