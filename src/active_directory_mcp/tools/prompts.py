"""
Prompts profissionais para Active Directory MCP.

Este módulo implementa 15 prompts especializados para gestores e analistas MSP,
facilitando operações complexas do Active Directory com contexto multi-step.

"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

from mcp.types import TextContent as Content
from .base import BaseTool
from ..core.ldap_manager import LDAPManager


logger = logging.getLogger("active-directory-mcp.prompts")


# =====================================================================
# CATÁLOGO DE PROMPTS - 15 PROMPTS PROFISSIONAIS
# =====================================================================

PROMPTS_CATALOG = [
    # ===== PROMPTS PARA GESTORES (7) =====
    {
        "name": "ad_security_audit",
        "description": "Gera auditoria completa de segurança do Active Directory identificando vulnerabilidades, contas inativas, senhas sem expiração e grupos críticos",
        "arguments": [
            {
                "name": "include_disabled",
                "description": "Incluir contas desabilitadas na auditoria (padrão: false)",
                "required": False
            }
        ]
    },
    {
        "name": "ad_user_growth_trends",
        "description": "Analisa tendências de crescimento de usuários no domínio para planejamento de capacidade e licenciamento",
        "arguments": [
            {
                "name": "period_months",
                "description": "Período de análise em meses (padrão: 6)",
                "required": False
            }
        ]
    },
    {
        "name": "ad_group_policy_compliance",
        "description": "Verifica compliance das políticas de grupo (GPOs) aplicadas e identifica desvios de padrões corporativos",
        "arguments": [
            {
                "name": "policy_type",
                "description": "Tipo de política a verificar: 'password', 'lockout', 'audit' (padrão: todas)",
                "required": False
            }
        ]
    },
    {
        "name": "ad_privileged_access_review",
        "description": "Revisão de acessos privilegiados para auditoria de compliance SOC2/ISO27001",
        "arguments": [
            {
                "name": "group_filter",
                "description": "Filtrar grupos específicos (ex: 'Admin', 'Domain') (padrão: todos privilegiados)",
                "required": False
            }
        ]
    },
    {
        "name": "ad_password_policy_health",
        "description": "Analisa saúde das políticas de senha e identifica contas em risco de comprometimento",
        "arguments": [
            {
                "name": "check_expiration",
                "description": "Verificar contas com senha próxima de expiração (padrão: true)",
                "required": False
            }
        ]
    },
    {
        "name": "ad_inactive_account_report",
        "description": "Relatório detalhado de contas inativas para limpeza e redução de superfície de ataque",
        "arguments": [
            {
                "name": "inactive_days",
                "description": "Dias sem login considerados inatividade (padrão: 90)",
                "required": False
            }
        ]
    },
    {
        "name": "ad_licensing_optimization",
        "description": "Otimização de licenças Microsoft 365 baseada em uso real do Active Directory",
        "arguments": [
            {
                "name": "license_type",
                "description": "Tipo de licença: 'E3', 'E5', 'F3' (padrão: todas)",
                "required": False
            }
        ]
    },

    # ===== PROMPTS PARA ANALISTAS (8) =====
    {
        "name": "ad_user_lookup",
        "description": "Busca rápida de usuário com informações essenciais para atendimento de suporte",
        "arguments": [
            {
                "name": "search_term",
                "description": "Nome, email ou username do usuário a buscar",
                "required": True
            }
        ]
    },
    {
        "name": "ad_password_reset_guide",
        "description": "Guia passo-a-passo para reset de senha de usuário com verificações de segurança",
        "arguments": [
            {
                "name": "username",
                "description": "Username do usuário para reset de senha",
                "required": True
            }
        ]
    },
    {
        "name": "ad_user_onboarding",
        "description": "Checklist e automação para onboarding de novo usuário baseado em template",
        "arguments": [
            {
                "name": "username",
                "description": "Username do novo usuário",
                "required": True
            },
            {
                "name": "template_user",
                "description": "Username do usuário template para copiar permissões (opcional)",
                "required": False
            }
        ]
    },
    {
        "name": "ad_user_offboarding",
        "description": "Checklist e automação para offboarding seguro de usuário (desabilitar, backup, remoção de grupos)",
        "arguments": [
            {
                "name": "username",
                "description": "Username do usuário para offboarding",
                "required": True
            }
        ]
    },
    {
        "name": "ad_group_membership_check",
        "description": "Verificação detalhada de membros de grupos para troubleshooting de permissões",
        "arguments": [
            {
                "name": "username",
                "description": "Username do usuário para verificar grupos",
                "required": True
            }
        ]
    },
    {
        "name": "ad_account_unlock",
        "description": "Desbloqueio de conta com validação de segurança e histórico de bloqueios",
        "arguments": [
            {
                "name": "username",
                "description": "Username da conta bloqueada",
                "required": True
            }
        ]
    },
    {
        "name": "ad_permission_troubleshooting",
        "description": "Troubleshooting de permissões de acesso a recursos (pastas, impressoras, aplicativos)",
        "arguments": [
            {
                "name": "username",
                "description": "Username do usuário com problema de acesso",
                "required": True
            },
            {
                "name": "resource_path",
                "description": "Caminho do recurso com problema (ex: \\\\servidor\\pasta)",
                "required": False
            }
        ]
    },
    {
        "name": "ad_computer_join_guide",
        "description": "Guia para ingressar computador no domínio com troubleshooting de erros comuns",
        "arguments": [
            {
                "name": "computer_name",
                "description": "Nome do computador a ingressar no domínio",
                "required": True
            }
        ]
    }
]


# =====================================================================
# HANDLERS DE PROMPTS
# =====================================================================

class PromptTools(BaseTool):
    """Ferramenta de prompts profissionais para Active Directory."""

    def __init__(self, ldap_manager: LDAPManager):
        """
        Inicializa ferramenta de prompts.

        Args:
            ldap_manager: Instância do gerenciador LDAP
        """
        super().__init__(ldap_manager)

    def list_prompts(self) -> List[Content]:
        """
        Lista todos os prompts disponíveis.

        Returns:
            Lista de prompts formatados para MCP
        """
        try:
            result = {
                "success": True,
                "total": len(PROMPTS_CATALOG),
                "prompts": PROMPTS_CATALOG,
                "categories": {
                    "gestores": [p for p in PROMPTS_CATALOG if p["name"].startswith("ad_") and any(
                        key in p["name"] for key in ["security", "growth", "policy", "privileged", "password_policy", "inactive_account", "licensing"]
                    )],
                    "analistas": [p for p in PROMPTS_CATALOG if p["name"].startswith("ad_") and any(
                        key in p["name"] for key in ["lookup", "reset_guide", "onboarding", "offboarding", "membership", "unlock", "troubleshooting", "join_guide"]
                    )]
                }
            }

            return self._format_response(result, "list_prompts")

        except Exception as e:
            return self._handle_ldap_error(e, "list_prompts")

    def get_prompt(self, name: str, arguments: Dict[str, Any]) -> List[Content]:
        """
        Executa prompt específico com argumentos fornecidos.

        Args:
            name: Nome do prompt a executar
            arguments: Argumentos do prompt

        Returns:
            Resultado do prompt formatado
        """
        try:
            # Mapear prompts para handlers
            prompt_handlers = {
                # Gestores
                "ad_security_audit": self._prompt_security_audit,
                "ad_user_growth_trends": self._prompt_user_growth_trends,
                "ad_group_policy_compliance": self._prompt_group_policy_compliance,
                "ad_privileged_access_review": self._prompt_privileged_access_review,
                "ad_password_policy_health": self._prompt_password_policy_health,
                "ad_inactive_account_report": self._prompt_inactive_account_report,
                "ad_licensing_optimization": self._prompt_licensing_optimization,

                # Analistas
                "ad_user_lookup": self._prompt_user_lookup,
                "ad_password_reset_guide": self._prompt_password_reset_guide,
                "ad_user_onboarding": self._prompt_user_onboarding,
                "ad_user_offboarding": self._prompt_user_offboarding,
                "ad_group_membership_check": self._prompt_group_membership_check,
                "ad_account_unlock": self._prompt_account_unlock,
                "ad_permission_troubleshooting": self._prompt_permission_troubleshooting,
                "ad_computer_join_guide": self._prompt_computer_join_guide
            }

            handler = prompt_handlers.get(name)
            if not handler:
                return self._format_response({
                    "success": False,
                    "error": f"Prompt '{name}' não encontrado",
                    "available": list(prompt_handlers.keys())
                }, "get_prompt")

            # Executar handler
            return handler(arguments)

        except Exception as e:
            return self._handle_ldap_error(e, f"get_prompt:{name}")

    # =====================================================================
    # HANDLERS DE PROMPTS PARA GESTORES
    # =====================================================================

    def _prompt_security_audit(self, args: Dict[str, Any]) -> List[Content]:
        """Auditoria de segurança completa."""
        include_disabled = args.get("include_disabled", False)

        result = {
            "prompt_name": "ad_security_audit",
            "timestamp": datetime.now().isoformat(),
            "format": "detalhado",
            "messages": [
                {
                    "role": "system",
                    "content": "Você está realizando uma auditoria de segurança do Active Directory para identificar vulnerabilidades e riscos."
                },
                {
                    "role": "user",
                    "content": f"""
Execute uma auditoria de segurança completa do Active Directory:

**ETAPAS DA AUDITORIA:**

1. **Contas Inativas** (use ad_get_inactive_users_by_days)
   - Identificar usuários sem login há mais de 90 dias
   - Separar contas habilitadas vs desabilitadas
   - {"Incluir contas desabilitadas na análise" if include_disabled else "Focar apenas em contas habilitadas"}

2. **Políticas de Senha** (use ad_get_password_policy_violations)
   - Identificar senhas sem expiração
   - Verificar senhas expiradas não alteradas
   - Listar contas sem requisito de senha complexa

3. **Grupos Privilegiados** (use ad_get_privileged_security_groups)
   - Auditar membros de Domain Admins
   - Verificar membros de Enterprise Admins
   - Revisar grupos com permissões administrativas

4. **Compliance de Contas**
   - Contas de serviço sem gestão adequada
   - Contas com delegação Kerberos irrestrita
   - Contas com reversible password encryption

**FORMATO DO RELATÓRIO:**
```
=== AUDITORIA DE SEGURANÇA AD ===
Data: {datetime.now().strftime("%Y-%m-%d %H:%M")}

📊 RESUMO EXECUTIVO:
- Total de vulnerabilidades: [número]
- Criticidade ALTA: [número]
- Criticidade MÉDIA: [número]
- Criticidade BAIXA: [número]

⚠️ ACHADOS CRÍTICOS:
1. [Descrição + impacto + recomendação]
2. [...]

📋 PLANO DE AÇÃO:
1. Curto prazo (< 7 dias): [ações]
2. Médio prazo (7-30 dias): [ações]
3. Longo prazo (> 30 dias): [ações]
```

Execute todas as ferramentas necessárias e gere o relatório completo.
"""
                }
            ]
        }

        return self._format_response(result, "ad_security_audit")

    def _prompt_user_growth_trends(self, args: Dict[str, Any]) -> List[Content]:
        """Análise de crescimento de usuários."""
        period_months = args.get("period_months", 6)

        result = {
            "prompt_name": "ad_user_growth_trends",
            "timestamp": datetime.now().isoformat(),
            "format": "compacto",
            "messages": [
                {
                    "role": "system",
                    "content": "Você está analisando tendências de crescimento de usuários para planejamento de capacidade."
                },
                {
                    "role": "user",
                    "content": f"""
Analise o crescimento de usuários no Active Directory para planejamento de capacidade:

**ANÁLISE REQUERIDA:**

1. **Listar Todos os Usuários** (use ad_list_users_with_filters)
   - Obter todos os usuários com atributo whenCreated
   - Período de análise: últimos {period_months} meses

2. **Calcular Crescimento**
   - Usuários criados por mês
   - Taxa de crescimento mensal
   - Projeção para próximos 3 meses

3. **Análise de OUs**
   - Identificar OUs com maior crescimento
   - Departamentos em expansão

**FORMATO DE SAÍDA:**
```
📈 CRESCIMENTO DE USUÁRIOS - {period_months} MESES

Período: {datetime.now() - timedelta(days=period_months*30)} até {datetime.now()}

📊 Estatísticas:
- Total atual: [número] usuários
- Crescimento total: [número] novos usuários
- Taxa média mensal: [número] usuários/mês

📅 Por Mês:
  Mês 1: +[X] usuários
  Mês 2: +[X] usuários
  ...

🎯 Projeção 3 meses:
  Estimativa: +[X] usuários
  Total projetado: [X] usuários

💡 Recomendações:
- Capacidade de licenças: [análise]
- Recursos de infraestrutura: [análise]
```

Execute ad_list_users_with_filters e gere a análise.
"""
                }
            ]
        }

        return self._format_response(result, "ad_user_growth_trends")

    def _prompt_group_policy_compliance(self, args: Dict[str, Any]) -> List[Content]:
        """Verificação de compliance de GPOs."""
        policy_type = args.get("policy_type", "todas")

        result = {
            "prompt_name": "ad_group_policy_compliance",
            "timestamp": datetime.now().isoformat(),
            "format": "detalhado",
            "messages": [
                {
                    "role": "system",
                    "content": "Você está verificando compliance de políticas de grupo do Active Directory."
                },
                {
                    "role": "user",
                    "content": f"""
Verifique compliance das políticas de grupo (GPOs) aplicadas no domínio:

**TIPO DE POLÍTICA:** {policy_type}

**VERIFICAÇÕES:**

1. **Política de Senha** (use ad_get_domain_security_policy_info)
   - Complexidade habilitada: SIM/NÃO
   - Tamanho mínimo: >= 12 caracteres
   - Histórico: >= 24 senhas
   - Idade máxima: <= 90 dias
   - Idade mínima: >= 1 dia

2. **Política de Bloqueio** (use ad_get_domain_security_policy_info)
   - Limite de tentativas: <= 5 tentativas
   - Duração do bloqueio: >= 30 minutos
   - Reset do contador: >= 30 minutos

3. **Auditoria de Segurança** (use ad_audit_administrative_accounts)
   - Auditoria de logon habilitada
   - Auditoria de alterações de conta
   - Auditoria de uso de privilégios

**PADRÕES DE COMPLIANCE:**
- SOC 2 Type II
- ISO 27001
- CIS Benchmarks

**FORMATO DE SAÍDA:**
```
✅ COMPLIANCE GPOs - {policy_type.upper()}

📋 Status Geral: [COMPLIANT / NÃO COMPLIANT]

Política de Senha:
  ✅ Complexidade: OK
  ❌ Tamanho mínimo: 8 (requer 12+)
  ...

Política de Bloqueio:
  ✅ Limite tentativas: 5
  ...

🔧 Ações Corretivas:
1. [Descrição + comando GPO]
2. [...]
```

Execute as ferramentas e gere o relatório de compliance.
"""
                }
            ]
        }

        return self._format_response(result, "ad_group_policy_compliance")

    def _prompt_privileged_access_review(self, args: Dict[str, Any]) -> List[Content]:
        """Revisão de acessos privilegiados."""
        group_filter = args.get("group_filter", "todos")

        result = {
            "prompt_name": "ad_privileged_access_review",
            "timestamp": datetime.now().isoformat(),
            "format": "detalhado",
            "messages": [
                {
                    "role": "system",
                    "content": "Você está revisando acessos privilegiados para auditoria de compliance."
                },
                {
                    "role": "user",
                    "content": f"""
Execute revisão de acessos privilegiados para compliance SOC2/ISO27001:

**FILTRO DE GRUPOS:** {group_filter}

**PASSOS:**

1. **Listar Grupos Privilegiados** (use ad_get_privileged_security_groups)
   - Domain Admins
   - Enterprise Admins
   - Schema Admins
   - Administrators
   - Account Operators
   - Backup Operators
   - Server Operators
   - Print Operators

2. **Para Cada Grupo:**
   - Listar membros (use ad_get_group_members_recursive)
   - Verificar última atividade de cada membro
   - Identificar contas de serviço vs humanas

3. **Análise de Risco:**
   - Contas privilegiadas sem MFA
   - Contas com senha sem expiração
   - Contas inativas com privilégios
   - Violações de princípio do menor privilégio

**FORMATO DE SAÍDA:**
```
🔐 REVISÃO DE ACESSOS PRIVILEGIADOS

Data: {datetime.now().strftime("%Y-%m-%d")}
Filtro: {group_filter}

📊 Resumo:
- Total grupos privilegiados: [X]
- Total contas privilegiadas: [X]
- Contas humanas: [X]
- Contas de serviço: [X]

⚠️ Riscos Identificados:
1. [Descrição risco + severidade + ação]
2. [...]

✅ Recomendações:
- Implementar JIT (Just-In-Time) access
- Habilitar MFA para todas contas privilegiadas
- Revisar mensalmente membros de grupos
```

Execute ad_get_privileged_security_groups e análise completa.
"""
                }
            ]
        }

        return self._format_response(result, "ad_privileged_access_review")

    def _prompt_password_policy_health(self, args: Dict[str, Any]) -> List[Content]:
        """Saúde das políticas de senha."""
        check_expiration = args.get("check_expiration", True)

        result = {
            "prompt_name": "ad_password_policy_health",
            "timestamp": datetime.now().isoformat(),
            "format": "compacto",
            "messages": [
                {
                    "role": "system",
                    "content": "Você está analisando saúde das políticas de senha do Active Directory."
                },
                {
                    "role": "user",
                    "content": f"""
Analise saúde das políticas de senha e identifique contas em risco:

**VERIFICAÇÃO DE EXPIRAÇÃO:** {"SIM" if check_expiration else "NÃO"}

**ANÁLISE:**

1. **Violações de Política** (use ad_get_password_policy_violations)
   - Senhas sem expiração
   - Senhas expiradas não alteradas
   - Contas sem requisito de senha

2. **Política do Domínio** (use ad_get_domain_security_policy_info)
   - Requisitos de complexidade
   - Idade máxima/mínima
   - Histórico de senhas

3. **Contas em Risco:**
   - Senhas antigas (> 180 dias)
   - {"Senhas próximas de expiração (< 7 dias)" if check_expiration else ""}
   - Senhas fracas detectáveis

**FORMATO DE SAÍDA:**
```
🔑 SAÚDE DE POLÍTICAS DE SENHA

Status Geral: [SAUDÁVEL / ATENÇÃO / CRÍTICO]

📊 Estatísticas:
- Contas com senha OK: [X] ([Y]%)
- Contas com violações: [X] ([Y]%)
- Contas em risco: [X] ([Y]%)

⚠️ Violações Detectadas:
1. [Tipo violação]: [X] contas
   Exemplo: user1, user2, ...
2. [...]

🎯 Ações Prioritárias:
1. [Ação + prazo + impacto]
2. [...]
```

Execute as ferramentas e gere análise de saúde.
"""
                }
            ]
        }

        return self._format_response(result, "ad_password_policy_health")

    def _prompt_inactive_account_report(self, args: Dict[str, Any]) -> List[Content]:
        """Relatório de contas inativas."""
        inactive_days = args.get("inactive_days", 90)

        result = {
            "prompt_name": "ad_inactive_account_report",
            "timestamp": datetime.now().isoformat(),
            "format": "detalhado",
            "messages": [
                {
                    "role": "system",
                    "content": "Você está gerando relatório de contas inativas para limpeza e segurança."
                },
                {
                    "role": "user",
                    "content": f"""
Gere relatório detalhado de contas inativas para limpeza:

**CRITÉRIO DE INATIVIDADE:** {inactive_days} dias sem login

**ANÁLISE:**

1. **Usuários Inativos** (use ad_get_inactive_users_by_days com days={inactive_days})
   - Separar por OU/departamento
   - Identificar contas habilitadas vs desabilitadas

2. **Computadores Inativos** (use ad_get_inactive_computers_by_days com days={inactive_days})
   - Listar computadores sem autenticação
   - Identificar computadores órfãos

3. **Análise de Impacto:**
   - Licenças desperdiçadas
   - Superfície de ataque reduzível
   - Espaço em disco recuperável

**FORMATO DE SAÍDA:**
```
🗑️ RELATÓRIO DE CONTAS INATIVAS

Critério: {inactive_days} dias sem login
Data: {datetime.now().strftime("%Y-%m-%d")}

📊 Resumo:
- Usuários inativos: [X]
- Computadores inativos: [X]
- Licenças recuperáveis: [X]
- Redução superfície ataque: [X]%

👥 Usuários Inativos por Departamento:
  TI: [X] usuários
  Vendas: [X] usuários
  ...

💻 Computadores Órfãos:
  Total: [X]
  Últimos 30 dias: [X]
  ...

🎯 Plano de Limpeza:
Fase 1: Desabilitar contas habilitadas inativas
Fase 2: Mover para OU de quarentena
Fase 3: Excluir após 30 dias de quarentena
```

Execute ad_get_inactive_users_by_days e ad_get_inactive_computers_by_days.
"""
                }
            ]
        }

        return self._format_response(result, "ad_inactive_account_report")

    def _prompt_licensing_optimization(self, args: Dict[str, Any]) -> List[Content]:
        """Otimização de licenças."""
        license_type = args.get("license_type", "todas")

        result = {
            "prompt_name": "ad_licensing_optimization",
            "timestamp": datetime.now().isoformat(),
            "format": "compacto",
            "messages": [
                {
                    "role": "system",
                    "content": "Você está otimizando uso de licenças Microsoft 365 baseado no Active Directory."
                },
                {
                    "role": "user",
                    "content": f"""
Otimize uso de licenças Microsoft 365 baseado em dados do AD:

**TIPO DE LICENÇA:** {license_type}

**ANÁLISE:**

1. **Inventário de Usuários** (use ad_list_users_with_filters)
   - Total de usuários habilitados
   - Usuários por departamento/OU

2. **Uso Real vs Licenças:**
   - Usuários inativos com licenças (use ad_get_inactive_users_by_days)
   - Contas de serviço com licenças desnecessárias
   - Licenças subutilizadas

3. **Oportunidades de Otimização:**
   - Downgrade E5 → E3 para usuários sem features premium
   - Downgrade E3 → F3 para Frontline Workers
   - Revogação de licenças de inativos

**FORMATO DE SAÍDA:**
```
💰 OTIMIZAÇÃO DE LICENÇAS M365

Tipo: {license_type}
Economia Potencial: R$ [valor]/mês

📊 Análise Atual:
- Licenças provisionadas: [X]
- Licenças em uso: [X]
- Licenças ociosas: [X]
- Taxa de utilização: [X]%

💡 Oportunidades:
1. Remover licenças de [X] inativos → Economia: R$ [valor]
2. Downgrade [X] usuários E5→E3 → Economia: R$ [valor]
3. Converter [X] usuários para F3 → Economia: R$ [valor]

🎯 Plano de Ação:
Fase 1: Revogar inativos (imediato)
Fase 2: Revisar downgrades (7 dias)
Fase 3: Implementar conversões (30 dias)

Economia Total Anual: R$ [valor]
```

Execute ad_list_users_with_filters e ad_get_inactive_users_by_days para análise.
"""
                }
            ]
        }

        return self._format_response(result, "ad_licensing_optimization")

    # =====================================================================
    # HANDLERS DE PROMPTS PARA ANALISTAS
    # =====================================================================

    def _prompt_user_lookup(self, args: Dict[str, Any]) -> List[Content]:
        """Busca rápida de usuário."""
        search_term = args.get("search_term", "")

        if not search_term:
            return self._format_response({
                "success": False,
                "error": "Parâmetro 'search_term' é obrigatório"
            }, "ad_user_lookup")

        result = {
            "prompt_name": "ad_user_lookup",
            "timestamp": datetime.now().isoformat(),
            "format": "compacto",
            "messages": [
                {
                    "role": "system",
                    "content": "Você está fazendo busca rápida de usuário para atendimento de suporte."
                },
                {
                    "role": "user",
                    "content": f"""
Busque informações essenciais do usuário para atendimento de suporte:

**TERMO DE BUSCA:** {search_term}

**PASSOS:**

1. **Buscar Usuário** (use ad_get_user_details_by_username ou ad_list_users_with_filters com filtro)
   - Tentar por username exato
   - Se não encontrar, buscar por nome ou email parcial

2. **Informações Essenciais:**
   - Nome completo
   - Email
   - Departamento/OU
   - Status da conta (habilitado/desabilitado)
   - Última data de login
   - Bloqueios ativos

3. **Verificações de Segurança:**
   - Grupos do usuário (use ad_get_user_group_memberships)
   - Permissões administrativas
   - Violações de política

**FORMATO DE SAÍDA:**
```
👤 INFORMAÇÕES DO USUÁRIO

Busca: {search_term}
Encontrado: SIM/NÃO

📋 Dados Básicos:
- Nome: [nome completo]
- Email: [email]
- Username: [username]
- Departamento: [depto]

📊 Status:
- Conta: [Habilitada/Desabilitada]
- Bloqueada: [Sim/Não]
- Último login: [data/hora]
- Senha expira em: [X dias]

🔐 Grupos (principais):
1. [grupo1]
2. [grupo2]
3. [...]

⚠️ Alertas:
- [Avisos ou problemas detectados]
```

Execute ad_get_user_details_by_username("{search_term}") e ad_get_user_group_memberships.
"""
                }
            ]
        }

        return self._format_response(result, "ad_user_lookup")

    def _prompt_password_reset_guide(self, args: Dict[str, Any]) -> List[Content]:
        """Guia de reset de senha."""
        username = args.get("username", "")

        if not username:
            return self._format_response({
                "success": False,
                "error": "Parâmetro 'username' é obrigatório"
            }, "ad_password_reset_guide")

        result = {
            "prompt_name": "ad_password_reset_guide",
            "timestamp": datetime.now().isoformat(),
            "format": "detalhado",
            "messages": [
                {
                    "role": "system",
                    "content": "Você está guiando um analista através do processo de reset de senha com segurança."
                },
                {
                    "role": "user",
                    "content": f"""
Execute reset de senha do usuário com verificações de segurança:

**USERNAME:** {username}

**CHECKLIST DE SEGURANÇA:**

1. ✅ **Validar Identidade do Solicitante**
   - Verificar se solicitante é o próprio usuário
   - Confirmar por canal secundário (telefone/Teams)

2. ✅ **Verificar Status da Conta** (use ad_get_user_details_by_username)
   - Confirmar conta existe
   - Verificar se está habilitada
   - Checar bloqueios ativos

3. ✅ **Gerar Senha Temporária**
   - Usar ad_reset_user_password_forced com force_change=True
   - Senha será gerada automaticamente
   - Usuário DEVE trocar no próximo login

4. ✅ **Desbloquear se Necessário**
   - Se conta bloqueada, desbloquear antes
   - Verificar histórico de bloqueios

**COMANDOS:**
```
1. ad_get_user_details_by_username(username="{username}")
2. ad_reset_user_password_forced(username="{username}", force_change=True)
3. Fornecer senha temporária ao usuário
```

**FORMATO DE SAÍDA:**
```
🔑 RESET DE SENHA

Usuário: {username}
Data: {datetime.now().strftime("%Y-%m-%d %H:%M")}

✅ Pré-verificações:
- Identidade confirmada: [Canal]
- Conta existe: SIM
- Conta habilitada: SIM
- Bloqueios: NENHUM

🔐 Senha Resetada:
- Senha temporária: [GERADA]
- Forçar troca no login: SIM
- Validade: Próximo login

📞 Orientações ao Usuário:
1. Use a senha temporária fornecida
2. Ao fazer login, será solicitada nova senha
3. Nova senha deve ter 12+ caracteres
4. Incluir maiúsculas, minúsculas, números e símbolos
5. Não reutilizar senhas antigas
```

Execute ad_get_user_details_by_username e ad_reset_user_password_forced.
"""
                }
            ]
        }

        return self._format_response(result, "ad_password_reset_guide")

    def _prompt_user_onboarding(self, args: Dict[str, Any]) -> List[Content]:
        """Onboarding de novo usuário."""
        username = args.get("username", "")
        template_user = args.get("template_user")

        if not username:
            return self._format_response({
                "success": False,
                "error": "Parâmetro 'username' é obrigatório"
            }, "ad_user_onboarding")

        template_info = f"baseado no usuário template '{template_user}'" if template_user else "com configuração padrão"

        result = {
            "prompt_name": "ad_user_onboarding",
            "timestamp": datetime.now().isoformat(),
            "format": "detalhado",
            "messages": [
                {
                    "role": "system",
                    "content": "Você está executando onboarding de novo usuário no Active Directory."
                },
                {
                    "role": "user",
                    "content": f"""
Execute onboarding completo de novo usuário {template_info}:

**NOVO USUÁRIO:** {username}
**TEMPLATE:** {template_user or "Configuração padrão"}

**CHECKLIST DE ONBOARDING:**

1. ✅ **Coletar Informações**
   - Nome completo
   - Email corporativo
   - Departamento
   - Cargo
   - Gestor
   - Data de início

2. ✅ **Preparar Grupos** {"(use ad_get_user_group_memberships do template)" if template_user else ""}
   - {"Copiar grupos do usuário template" if template_user else "Aplicar grupos padrão do departamento"}
   - Adicionar grupo do departamento
   - Adicionar grupos de aplicativos necessários

3. ✅ **Criar Conta** (use ad_create_user_account)
   - Username: {username}
   - Senha temporária (complexa)
   - Force password change: SIM
   - OU correta do departamento

4. ✅ **Configurar Grupos** (use ad_add_member_to_group)
   - Adicionar aos grupos identificados
   - Verificar permissões aplicadas

5. ✅ **Validação Final**
   - Confirmar conta criada (use ad_get_user_details_by_username)
   - Verificar grupos (use ad_get_user_group_memberships)
   - Testar autenticação

**FORMATO DE SAÍDA:**
```
✨ ONBOARDING DE USUÁRIO

Novo Usuário: {username}
Template: {template_user or "Padrão"}
Data: {datetime.now().strftime("%Y-%m-%d")}

📋 Informações Coletadas:
- Nome: [a coletar]
- Email: [a coletar]
- Departamento: [a coletar]
- Cargo: [a coletar]

🔐 Conta Criada:
- Username: {username}
- Senha temporária: [GERADA]
- OU: [OU do departamento]
- Status: Habilitada

👥 Grupos Aplicados:
1. [grupo1] - Departamento
2. [grupo2] - Aplicativo X
3. [grupo3] - Aplicativo Y

✅ Checklist Completo:
- Conta criada: ✅
- Grupos aplicados: ✅
- Email configurado: ✅
- Validação final: ✅

📧 Próximos Passos:
1. Enviar credenciais ao usuário
2. Agendar treinamento de sistemas
3. Provisionar equipamentos
```

{"Execute ad_get_user_group_memberships('"+template_user+"') para copiar configuração." if template_user else "Execute ad_create_user_account com dados coletados."}
"""
                }
            ]
        }

        return self._format_response(result, "ad_user_onboarding")

    def _prompt_user_offboarding(self, args: Dict[str, Any]) -> List[Content]:
        """Offboarding de usuário."""
        username = args.get("username", "")

        if not username:
            return self._format_response({
                "success": False,
                "error": "Parâmetro 'username' é obrigatório"
            }, "ad_user_offboarding")

        result = {
            "prompt_name": "ad_user_offboarding",
            "timestamp": datetime.now().isoformat(),
            "format": "detalhado",
            "messages": [
                {
                    "role": "system",
                    "content": "Você está executando offboarding seguro de usuário do Active Directory."
                },
                {
                    "role": "user",
                    "content": f"""
Execute offboarding seguro e completo do usuário:

**USUÁRIO:** {username}

**CHECKLIST DE OFFBOARDING (CRÍTICO):**

1. ✅ **Backup de Dados**
   - ⚠️ ANTES de qualquer ação, confirmar backup realizado
   - Arquivos pessoais
   - Emails (exportar mailbox)
   - OneDrive

2. ✅ **Desabilitar Conta** (use ad_disable_user_account_access)
   - NÃO excluir imediatamente
   - Apenas desabilitar login
   - Manter por 90 dias

3. ✅ **Remover de Grupos** (use ad_get_user_group_memberships + ad_remove_member_from_group)
   - Listar todos os grupos do usuário
   - Remover de TODOS os grupos, exceto "Domain Users"
   - Especial atenção a grupos administrativos

4. ✅ **Revogar Sessões Ativas**
   - Forçar logoff de todos os dispositivos
   - Revogar tokens de autenticação

5. ✅ **Transferir Propriedades**
   - Grupos gerenciados pelo usuário
   - Objetos criados pelo usuário
   - Delegações de permissão

6. ✅ **Mover para OU de Quarentena**
   - OU: "Desabilitadas/Ex-funcionários"
   - Manter por período de retenção

7. ✅ **Documentar Offboarding**
   - Data de desligamento
   - Responsável pela execução
   - Itens transferidos

**FORMATO DE SAÍDA:**
```
🚪 OFFBOARDING DE USUÁRIO

Usuário: {username}
Data: {datetime.now().strftime("%Y-%m-%d %H:%M")}
Executado por: [analista]

⚠️ PRÉ-REQUISITOS:
- Backup de dados: [CONFIRMAR ANTES DE PROSSEGUIR]
- Autorização: [Ticket/Aprovação]

✅ Ações Executadas:

1. Conta Desabilitada:
   - Status: Desabilitada
   - Data: {datetime.now().strftime("%Y-%m-%d")}

2. Grupos Removidos ({len([])})  total):
   - [grupo1] ❌ Removido
   - [grupo2] ❌ Removido
   - Domain Users ✅ Mantido

3. Sessões Revogadas:
   - Tokens revogados: SIM
   - Logoff forçado: SIM

4. Movido para OU Quarentena:
   - OU destino: OU=Desabilitadas,OU=Usuarios
   - Data retenção: {(datetime.now() + timedelta(days=90)).strftime("%Y-%m-%d")}

📋 Itens Transferidos:
- Grupos gerenciados: [lista]
- Objetos de propriedade: [lista]

⏰ Próximos Passos:
- Revisar em 30 dias
- Excluir permanentemente em 90 dias
- Liberar licenças M365
```

Execute ad_get_user_details_by_username, ad_disable_user_account_access, ad_get_user_group_memberships e removals.
"""
                }
            ]
        }

        return self._format_response(result, "ad_user_offboarding")

    def _prompt_group_membership_check(self, args: Dict[str, Any]) -> List[Content]:
        """Verificação de membros de grupos."""
        username = args.get("username", "")

        if not username:
            return self._format_response({
                "success": False,
                "error": "Parâmetro 'username' é obrigatório"
            }, "ad_group_membership_check")

        result = {
            "prompt_name": "ad_group_membership_check",
            "timestamp": datetime.now().isoformat(),
            "format": "compacto",
            "messages": [
                {
                    "role": "system",
                    "content": "Você está verificando membros de grupos para troubleshooting de permissões."
                },
                {
                    "role": "user",
                    "content": f"""
Verifique detalhadamente os grupos do usuário para troubleshooting:

**USUÁRIO:** {username}

**ANÁLISE:**

1. **Listar Grupos** (use ad_get_user_group_memberships)
   - Todos os grupos diretos
   - Grupos aninhados (nested groups)

2. **Categorizar Grupos:**
   - Grupos de segurança
   - Grupos de distribuição
   - Grupos administrativos
   - Grupos de aplicativos

3. **Análise de Permissões:**
   - Identificar grupos que concedem permissões administrativas
   - Verificar grupos de acesso a recursos
   - Detectar grupos redundantes

**FORMATO DE SAÍDA:**
```
👥 GRUPOS DO USUÁRIO

Usuário: {username}
Total de Grupos: [X]

📊 Por Categoria:

🔐 Grupos Administrativos ([X]):
  1. Domain Admins
  2. [outros...]

💼 Grupos de Departamento ([X]):
  1. TI-Team
  2. [outros...]

📱 Grupos de Aplicativos ([X]):
  1. SharePoint-Users
  2. VPN-Access
  3. [outros...]

📧 Grupos de Distribuição ([X]):
  1. All-Company
  2. [outros...]

⚠️ Alertas:
- Grupos administrativos: [alertar se presente]
- Grupos órfãos: [grupos sem descrição/uso]
- Aninhamento profundo: [>3 níveis]

💡 Recomendações:
- [Sugestões de otimização]
```

Execute ad_get_user_group_memberships("{username}").
"""
                }
            ]
        }

        return self._format_response(result, "ad_group_membership_check")

    def _prompt_account_unlock(self, args: Dict[str, Any]) -> List[Content]:
        """Desbloqueio de conta."""
        username = args.get("username", "")

        if not username:
            return self._format_response({
                "success": False,
                "error": "Parâmetro 'username' é obrigatório"
            }, "ad_account_unlock")

        result = {
            "prompt_name": "ad_account_unlock",
            "timestamp": datetime.now().isoformat(),
            "format": "detalhado",
            "messages": [
                {
                    "role": "system",
                    "content": "Você está desbloqueando conta com validações de segurança."
                },
                {
                    "role": "user",
                    "content": f"""
Desbloqueie a conta do usuário com validações de segurança:

**USUÁRIO:** {username}

**PROCEDIMENTO:**

1. ✅ **Verificar Status** (use ad_get_user_details_by_username)
   - Confirmar conta está bloqueada
   - Verificar motivo do bloqueio
   - Checar histórico de bloqueios recentes

2. ✅ **Validação de Segurança**
   - ⚠️ Se bloqueios frequentes (>3 em 24h): ALERTA DE SEGURANÇA
   - Pode ser tentativa de acesso não autorizado
   - Confirmar com usuário antes de desbloquear

3. ✅ **Desbloquear** (use ad_modify_user_attributes para remover lockout)
   - Nota: AD não tem comando direto unlock via LDAP
   - Use: ad_modify_user_attributes com atributo lockoutTime = 0

4. ✅ **Validação Pós-Unlock**
   - Confirmar conta desbloqueada
   - Orientar usuário sobre senha correta
   - Monitorar novos bloqueios

**ALERTAS DE SEGURANÇA:**
- Se bloqueios repetidos: Investigar possível comprometimento
- Se bloqueio após horário: Verificar acesso remoto
- Se bloqueio de conta privilegiada: Alerta HIGH

**FORMATO DE SAÍDA:**
```
🔓 DESBLOQUEIO DE CONTA

Usuário: {username}
Data: {datetime.now().strftime("%Y-%m-%d %H:%M")}

📊 Status Pré-Unlock:
- Conta bloqueada: SIM
- Motivo: Tentativas de senha incorreta
- Bloqueios últimas 24h: [X]

⚠️ Avaliação de Segurança:
- Risco: [BAIXO/MÉDIO/ALTO]
- Padrão: [Normal/Suspeito]
- Ação: [Prosseguir/Investigar]

✅ Desbloqueio Executado:
- Método: lockoutTime = 0
- Status: DESBLOQUEADA
- Validação: OK

📞 Orientações ao Usuário:
1. Verificar tecla Caps Lock
2. Digitar senha com atenção
3. Senha diferencia maiúsculas/minúsculas
4. Se problema persistir, solicitar reset

🔍 Monitoramento:
- Acompanhar próximas 24h
- Alertar se novo bloqueio
```

Execute ad_get_user_details_by_username e ad_modify_user_attributes para unlock.
"""
                }
            ]
        }

        return self._format_response(result, "ad_account_unlock")

    def _prompt_permission_troubleshooting(self, args: Dict[str, Any]) -> List[Content]:
        """Troubleshooting de permissões."""
        username = args.get("username", "")
        resource_path = args.get("resource_path")

        if not username:
            return self._format_response({
                "success": False,
                "error": "Parâmetro 'username' é obrigatório"
            }, "ad_permission_troubleshooting")

        resource_info = f" ao recurso '{resource_path}'" if resource_path else ""

        result = {
            "prompt_name": "ad_permission_troubleshooting",
            "timestamp": datetime.now().isoformat(),
            "format": "detalhado",
            "messages": [
                {
                    "role": "system",
                    "content": "Você está fazendo troubleshooting de permissões de acesso a recursos."
                },
                {
                    "role": "user",
                    "content": f"""
Faça troubleshooting de permissões de acesso{resource_info}:

**USUÁRIO:** {username}
**RECURSO:** {resource_path or "A identificar"}

**DIAGNÓSTICO:**

1. ✅ **Verificar Conta** (use ad_get_user_details_by_username)
   - Conta habilitada: SIM/NÃO
   - Conta bloqueada: SIM/NÃO
   - Última autenticação: [quando]

2. ✅ **Verificar Grupos** (use ad_get_user_group_memberships)
   - Listar todos os grupos do usuário
   - Identificar grupos com acesso ao recurso
   - Verificar grupos aninhados

3. ✅ **Verificar Permissões Efetivas** (use ad_get_user_effective_permissions)
   - Permissões via grupos de segurança
   - Permissões diretas (se houver)
   - Permissões negadas (deny sobrepõe allow)

4. ✅ **Verificar Política de Grupo**
   - GPOs aplicadas à conta
   - GPOs que podem bloquear acesso
   - Software Restriction Policies

5. ✅ **Checklist de Troubleshooting:**
   - Usuário está no grupo correto?
   - Grupo tem permissão no recurso?
   - Há deny permissions?
   - GPO está bloqueando?
   - Cache de credenciais desatualizado?

**FORMATO DE SAÍDA:**
```
🔍 TROUBLESHOOTING DE PERMISSÕES

Usuário: {username}
Recurso: {resource_path or "N/A"}
Data: {datetime.now().strftime("%Y-%m-%d %H:%M")}

✅ Status da Conta:
- Habilitada: [SIM/NÃO]
- Bloqueada: [SIM/NÃO]
- Último login: [data]

👥 Grupos do Usuário ({len([])} total):
Grupos com acesso ao recurso:
  ✅ [grupo1] - Acesso Leitura
  ✅ [grupo2] - Acesso Modificação
  ❌ [grupo_necessario] - FALTANDO

🔐 Permissões Efetivas:
- Leitura: [ALLOW/DENY]
- Escrita: [ALLOW/DENY]
- Modificação: [ALLOW/DENY]
- Controle Total: [ALLOW/DENY]

⚠️ Problemas Identificados:
1. [Descrição do problema]
   Causa: [causa raiz]
   Solução: [ação corretiva]

2. [...]

🎯 Solução Recomendada:
Passo 1: [ação específica]
Passo 2: [...]

Tempo estimado: [X minutos]
Requer aprovação: [SIM/NÃO]
```

Execute ad_get_user_details_by_username, ad_get_user_group_memberships e ad_get_user_effective_permissions.
"""
                }
            ]
        }

        return self._format_response(result, "ad_permission_troubleshooting")

    def _prompt_computer_join_guide(self, args: Dict[str, Any]) -> List[Content]:
        """Guia de ingresso no domínio."""
        computer_name = args.get("computer_name", "")

        if not computer_name:
            return self._format_response({
                "success": False,
                "error": "Parâmetro 'computer_name' é obrigatório"
            }, "ad_computer_join_guide")

        result = {
            "prompt_name": "ad_computer_join_guide",
            "timestamp": datetime.now().isoformat(),
            "format": "detalhado",
            "messages": [
                {
                    "role": "system",
                    "content": "Você está guiando o processo de ingresso de computador no domínio."
                },
                {
                    "role": "user",
                    "content": f"""
Guie o processo de ingresso do computador no domínio:

**COMPUTADOR:** {computer_name}

**PRÉ-REQUISITOS:**

1. ✅ **Verificações de Rede**
   - Ping para Domain Controller: OK?
   - Resolução DNS do domínio: OK?
   - Porta 389 (LDAP) aberta: OK?
   - Porta 88 (Kerberos) aberta: OK?

2. ✅ **Criar Objeto Computer** (use ad_create_computer_account)
   - Nome: {computer_name}
   - OU: [OU de Workstations ou departamento]
   - Descrição: [informações do equipamento]

**PROCEDIMENTO NO COMPUTADOR:**

```powershell
# 1. Configurar DNS (apontar para DC)
# 2. Testar conectividade
Test-Connection dc.dominio.local

# 3. Ingressar no domínio
Add-Computer -DomainName dominio.local -Credential dominio\\admin -Restart
```

**TROUBLESHOOTING DE ERROS COMUNS:**

❌ **Erro: "Nome duplicado na rede"**
- Causa: Objeto computer já existe
- Solução: Verificar ad_get_computer_details_by_name("{computer_name}") e ad_delete_computer_account_permanently se órfão

❌ **Erro: "Não foi possível contatar controlador de domínio"**
- Causa: Problema DNS ou rede
- Solução: Verificar DNS settings e conectividade

❌ **Erro: "Credenciais inválidas"**
- Causa: Senha incorreta ou conta bloqueada
- Solução: Verificar credenciais do usuário admin

❌ **Erro: "Acesso negado"**
- Causa: Usuário sem permissão para ingressar computadores
- Solução: Usar conta com privilégio Domain Join

**FORMATO DE SAÍDA:**
```
💻 INGRESSO NO DOMÍNIO

Computador: {computer_name}
Domínio: [dominio.local]
Data: {datetime.now().strftime("%Y-%m-%d %H:%M")}

✅ Pré-requisitos:
- Objeto Computer criado: ✅
- DNS configurado: [Validar no computador]
- Conectividade DC: [Validar no computador]

📋 Passos de Execução:

1. Configurar DNS:
   DNS Primário: [IP do DC]
   DNS Secundário: [IP do DC2]

2. Testar Conectividade:
   ping dc.dominio.local
   nslookup dominio.local

3. Ingressar no Domínio:
   [Comando PowerShell ou GUI]

4. Reiniciar Computador:
   Aguardar reinicialização completa

5. Validar Ingresso:
   Fazer login com conta de domínio
   Executar: whoami /groups

🔧 Troubleshooting:
Se erro [X]: [solução específica]

✅ Validação Final:
- Computador aparece no AD: (use ad_get_computer_details_by_name)
- Usuário consegue logar: [SIM/NÃO]
- GPOs sendo aplicadas: gpresult /r
```

Execute ad_create_computer_account("{computer_name}") primeiro.
"""
                }
            ]
        }

        return self._format_response(result, "ad_computer_join_guide")

    def get_schema_info(self) -> Dict[str, Any]:
        """
        Retorna informações de schema das ferramentas de prompts.

        Returns:
            Dicionário com schema de prompts
        """
        return {
            "total_prompts": len(PROMPTS_CATALOG),
            "categories": {
                "gestores": 7,
                "analistas": 8
            },
            "prompts": PROMPTS_CATALOG
        }


# ============= HANDLERS PARA MCP PROTOCOL =============

async def handle_get_prompt(name: str, arguments: Dict[str, Any], ldap_manager) -> dict:
    """
    Handler para prompts/get (MCP protocol).

    Args:
        name: Nome do prompt
        arguments: Argumentos do prompt
        ldap_manager: Instância do LDAPManager

    Returns:
        Resultado do prompt no formato MCP
    """
    # Verificar se prompt existe
    prompt = next((p for p in PROMPTS_CATALOG if p["name"] == name), None)
    if not prompt:
        raise ValueError(f"Prompt não encontrado: {name}")

    # Instanciar PromptTools e executar prompt
    prompt_tools = PromptTools(ldap_manager)
    result = prompt_tools.get_prompt(name, arguments)

    # Converter result (List[Content]) para formato MCP esperado
    # O formato MCP de prompts/get deve retornar: {"description": ..., "messages": [...]}
    if isinstance(result, list) and len(result) > 0:
        content = result[0]
        if hasattr(content, 'text'):
            text = content.text
        else:
            text = str(content)

        return {
            "description": f"Prompt {name} executado",
            "messages": [
                {
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": text
                    }
                }
            ]
        }

    return {
        "description": f"Prompt {name} executado",
        "messages": [
            {
                "role": "user",
                "content": {
                    "type": "text",
                    "text": str(result)
                }
            }
        ]
    }
