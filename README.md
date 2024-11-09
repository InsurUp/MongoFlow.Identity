# MongoFlow.Identity

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
