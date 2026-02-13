# S.H.I.E.L.D. — Secure Heuristic Intelligence Enforcement & Layered Defense

Sistema de vigilância e contenção para agentes de IA com arquitetura multicamadas:

1. **Perimeter**: recursos, rede, arquivos e rate limits.
2. **Heuristics**: padrões suspeitos e anomalias comportamentais.
3. **Local AI Guardian (novo)**: IA local/offline para detecção de desvio semântico-comportamental.
4. **Oracle (LLM local)**: análise de intenção com Ollama.
5. **Enforcement**: bloqueio, sandbox, quarentena e kill switch.

## Instalação

```bash
chmod +x setup.sh
./setup.sh
source venv/bin/activate
```

> Para pular instalação do Ollama: `INSTALL_OLLAMA=false ./setup.sh`
> Para instalar ferramentas de desenvolvimento e testes: `INSTALL_DEV=true ./setup.sh`

## Execução

```bash
python demo_shield.py
```

## Verificação de saúde

```bash
python healthcheck.py
```

## Configuração

Use `config.example.json` como base para `config.json`.

### Novos parâmetros relevantes

- `oracle.always_analyze`: força Oracle em toda ação.
- `oracle.min_escalation_level`: nível mínimo para escalar ao Oracle.
- `oracle.enable_caching` + `oracle.cache_ttl_seconds`: cache com expiração.
- `local_ai.*`: parâmetros da nova IA local offline.

## Segurança operacional

- Execute em ambiente isolado para testes.
- Revise decisões `CRITICAL` com aprovação humana.
- `setup.sh` usa instalação via script remoto para Ollama; avalie sua política de segurança antes de usar em produção.


## Dependências

- `requirements-runtime.txt`: execução em produção.
- `requirements-dev.txt`: runtime + testes/lint.
- `requirements.txt`: compatibilidade (aponta para dev).
