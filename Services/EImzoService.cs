using Newtonsoft.Json;
using System.Net.Http.Headers;
using EImzoMVC.Models;

namespace EImzoMVC.Services;

public class EImzoService
{
    private readonly HttpClient _httpClient;
    private readonly EImzoConfig _config;

    public EImzoService(EImzoConfig config, IHttpClientFactory httpClientFactory)
    {
        _config = config;
        _httpClient = httpClientFactory.CreateClient("EImzoClient");
        if (!string.IsNullOrEmpty(_config.Domain))
        {
            _httpClient.DefaultRequestHeaders.Add("Host", _config.Domain);
        }
    }

    public async Task<EImzoChallangeResultDto> ChallengeAsync()
    {
        using var res = await _httpClient.GetAsync($"{_config.ServerUri}/frontend/challenge");
        var content = await res.Content.ReadAsStringAsync();
        if (!res.IsSuccessStatusCode) throw new HttpRequestException(content);
        return JsonConvert.DeserializeObject<EImzoChallangeResultDto>(content)!;
    }

    public async Task<EImzoAuthResultDto> AuthAsync(string signData)
    {
        using var res = await _httpClient.PostAsync($"{_config.ServerUri}/backend/auth", new StringContent(signData));
        var content = await res.Content.ReadAsStringAsync();
        if (!res.IsSuccessStatusCode) throw new HttpRequestException(content);
        return JsonConvert.DeserializeObject<EImzoAuthResultDto>(content)!;
    }

    public async Task<EImzoTimeStampResultDto> TimeStampPkcs7Async(string data)
    {
        using var res = await _httpClient.PostAsync($"{_config.ServerUri}/frontend/timestamp/pkcs7", new StringContent(data));
        var content = await res.Content.ReadAsStringAsync();
        if (!res.IsSuccessStatusCode) throw new HttpRequestException(content);
        return JsonConvert.DeserializeObject<EImzoTimeStampResultDto>(content)!;
    }

    // Backwards compatible wrapper used by controller
    public async Task<EImzoTimeStampResultDto> TimeStamp(string base64Pkcs7)
    {
        return await TimeStampPkcs7Async(base64Pkcs7);
    }

    public async Task<EImzoVerifyResultDto> VerifyAttachedAsync(string signData)
    {
        using var res = await _httpClient.PostAsync($"{_config.ServerUri}/backend/pkcs7/verify/attached", new StringContent(signData));
        var content = await res.Content.ReadAsStringAsync();
        if (!res.IsSuccessStatusCode) throw new HttpRequestException(content);
        return JsonConvert.DeserializeObject<EImzoVerifyResultDto>(content)!;
    }

    // Backwards compatible wrapper
    public async Task<EImzoVerifyResultDto> VerifyAttached(EImzoVerifyDto dto)
    {
        return await VerifyAttachedAsync(dto.SignData);
    }
}
