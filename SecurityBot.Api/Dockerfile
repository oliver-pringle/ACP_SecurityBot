FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY BasicSubscriptionBot.Api/BasicSubscriptionBot.Api.csproj BasicSubscriptionBot.Api/
RUN dotnet restore BasicSubscriptionBot.Api/BasicSubscriptionBot.Api.csproj

COPY BasicSubscriptionBot.Api/ BasicSubscriptionBot.Api/
RUN dotnet publish BasicSubscriptionBot.Api/BasicSubscriptionBot.Api.csproj -c Release -o /app /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
COPY --from=build /app .

ENV ASPNETCORE_URLS=http://+:5000
ENV ConnectionStrings__Sqlite="Data Source=/data/basicsubscriptionbot.db;Cache=Shared"

# The aspnet base image ships with a non-root `app` user (UID is exposed via
# $APP_UID, currently 1654 in .NET 10). Drop privileges before running.
# NOTE: the SQLite bind-mount target /data must be writable by this UID on the
# host — see the README for the one-time `chown 1654:1654 ./data` step.
USER $APP_UID

EXPOSE 5000
ENTRYPOINT ["dotnet", "BasicSubscriptionBot.Api.dll"]
