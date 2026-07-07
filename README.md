curl -i https://api.anthropic.com/v1/messages -H "x-api-key: test" -H "anthropic-version: 2023-06-01" -H "content-type: application/json" -d "{\"model\":\"claude-sonnet-5\",\"max_tokens\":10,\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}"


$headers = @{
  "x-api-key" = "test"
  "anthropic-version" = "2023-06-01"
  "content-type" = "application/json"
}
$body = '{"model":"claude-sonnet-5","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}'
Invoke-WebRequest -Uri "https://api.anthropic.com/v1/messages" -Method POST -Headers $headers -Body $body
