var builder = DistributedApplication.CreateBuilder(args);

builder.AddProject<Projects.SecureAuthApi>("secureauthapi");

builder.Build().Run();
