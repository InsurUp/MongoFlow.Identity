# MongoFlow.Identity

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![.NET C#](https://img.shields.io/badge/.NET-C%23-blue)](https://docs.microsoft.com/en-us/dotnet/csharp/)~~~~
[![NuGet](https://img.shields.io/nuget/v/MongoFlow.Identity)](https://www.nuget.org/packages/MongoFlow.Identity)

> [!WARNING]
> This package is not ready for production use. It is still in development and should not be used in a production environment.
>
> We welcome your feedback! You can reach us by [opening a GitHub issue](https://github.com/InsurUp/MongoFlow.Identity/issues).

A MongoDB provider for ASP.NET Core Identity that leverages [MongoFlow](https://github.com/InsurUpOrg/MongoFlow) for seamless integration.

## Installation 

```bash
dotnet add package MongoFlow.Identity
```

## Usage

You can call `AddMongoFlowStores<TVault>` on `IdentityBuilder` to configure the MongoDB stores. For example:

```csharp
services.AddIdentityCore<MongoUser>()
            .AddRoles<MongoRole>()
            .AddMongoFlowStores<MyVault>();
```

You can customize MongoUser and MongoRole by inheriting.

```csharp
public class MyUser : MongoUser
{
    public string MyProperty { get; set; }
}

public class MyRole : MongoRole
{
    public string MyProperty { get; set; }
}
```

or with custom key

```csharp
public class MyUser : MongoUser<Guid>
{
    public string MyProperty { get; set; }
}

public class MyRole : MongoRole<Guid>
{
    public string MyProperty { get; set; }
}
```