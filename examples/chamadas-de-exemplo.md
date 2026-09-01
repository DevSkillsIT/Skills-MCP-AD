# Chamadas de exemplo — instância multi-AD

Todas via JSON-RPC em `POST /mcp`, com `Authorization: Bearer $AD_MCP_API_TOKEN`.

## Descobrir os servidores

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call",
 "params":{"name":"ad_list_ad_servers","arguments":{}}}
```

Devolve, por servidor: `ad_server` (o valor a usar), apelidos, domínio,
`controlador_de_dominio`, host, base DN, OUs e estado da conexão.
Credenciais de bind não aparecem.

## Ler de um AD específico

```json
{"jsonrpc":"2.0","id":2,"method":"tools/call",
 "params":{"name":"ad_list_users_with_filters",
           "arguments":{"ad_server":"cliente-exemplo"}}}
```

O `ad_server` aceita o nome do servidor, um apelido, o domínio
(`exemplo.local`) ou o hostname do controlador de domínio
(`DCEXEMPLO01`).

## Procurar sem saber em qual AD

```json
{"jsonrpc":"2.0","id":3,"method":"tools/call",
 "params":{"name":"ad_get_user_details_by_username",
           "arguments":{"username":"adriano.fante"}}}
```

Sem `ad_server` (ou com `"todos"`), a busca roda em todos e a resposta traz
`encontrado_em`, `sem_resultado_em` e, se houver, `servidores_com_falha`.

## Escrever — exige servidor e confirmação

```json
{"jsonrpc":"2.0","id":4,"method":"tools/call",
 "params":{"name":"ad_modify_user_attributes",
           "arguments":{"ad_server":"cliente-exemplo",
                        "username":"joao.silva",
                        "attributes":{"title":"Analista"},
                        "client_confirmation":"cliente-exemplo"}}}
```

Sem `ad_server` a chamada é recusada (escrita nunca roda em todos).
Sem `client_confirmation` a resposta diz qual valor usar, em `confirm_with`.
Alternativa para automação: `automation_token`.

## Diagnóstico

```bash
curl -s http://127.0.0.1:8853/health | python3 -m json.tool
```

Sem autenticação, reporta cada AD separadamente. Servidor com status
`nao_conectado` ainda não foi usado nesta execução — o health não afirma nada
sobre a saúde dele.
