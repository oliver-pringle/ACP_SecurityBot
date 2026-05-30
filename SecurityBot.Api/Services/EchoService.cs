using SecurityBot.Api.Data;
using SecurityBot.Api.Models;

namespace SecurityBot.Api.Services;

public class EchoService
{
    private readonly EchoRepository _repo;
    public EchoService(EchoRepository repo) => _repo = repo;

    public Task<EchoRecord> RecordAsync(string message) => _repo.InsertAsync(message);
    public Task<EchoRecord?> GetAsync(long id) => _repo.GetAsync(id);
}
