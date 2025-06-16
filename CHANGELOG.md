# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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