# Change Log


## [1.7.0] -- 2022-08-10

### Breaking Changes

### Added

### Changed
- (Core) Bump Microsoft.AspNetCore.Authentication.JwtBearer to 6.0.8
- (Infrastructure) Bump Microsoft.EntityFrameworkCore to 6.0.8

### Fixed

### Removed
- Removed generic parameter `TUserKey` from extension methods.

### Security

### Deprecated


## [1.6.0] -- 2022-08-08

Refactor namespaces

### Breaking Changes
- Namespaces

### Added
- Added `RefreshTokenValidator`
- Added AuthEndpoints.Infrastructure project
- Added `IRefreshTokenRepository` to Core
- Added `RefreshTokenRepository` to Infrastructure
- Added extensions for `AuthEndpointsBuilder`, for configuring RefreshTokenRepository
- Added additional check to refresh token validator. `RefreshTokenValidator.ValidateRefreshTokenAsync` will return invalid `TokenValidationResult` if refresh jwt is not stored in the database.

### Changed
- Namespaces in Core project.

### Fixed
- [#81](https://github.com/madeyoga/AuthEndpoints/issues/81)

### Removed
- Removed `IjwtValidator`
- Removed `DefaultJwtValidator`

### Security

### Deprecated
- Deprecate the use of `AuthEndpointsBuilder.AddAllEndpointDefinitions`. Please use `AuthEndpointsBuilder.AddAuthEndpointDefinitions`
- Deprecate the use of `WebApplication.MapAuthEndpoints`. Please use `WebApplication.MapEndpoints` instead


## [1.5.0] -- 2022-08-02

Refactor core services

### Added
- Added `IAccessTokenGenerator`, `IRefreshTokenGenerator`, and TokenGeneratorService
- Added default implementations for access token generator and refresh token generator

### Changed

### Fixed

### Removed
- Removed `IjwtFactory`
- Removed `DefaultJwtFactory`

### Security
