# Política de Segurança — PROCEDA Agent

A segurança do **PROCEDA Agent** é parte importante da proteção do processo de licenciamento do PROCEDA Writer.

Este documento descreve como relatar possíveis vulnerabilidades e os limites da política de segurança. Para informações sobre finalidade, privacidade e auditoria do Agent, consulte o [README.md](README.md).

## Versões suportadas

As correções de segurança são direcionadas às versões atualmente mantidas do PROCEDA Agent. Versões antigas podem deixar de receber atualizações.

Ao relatar uma vulnerabilidade, informe a versão ou o commit afetado para que o mantenedor possa avaliar o impacto.

## Reporte de vulnerabilidades

**Não divulgue vulnerabilidades ainda não corrigidas em issues, discussions ou pull requests públicos.**

Utilize a opção **Security → Report a vulnerability** do repositório, caso o reporte privado de vulnerabilidades esteja habilitado no GitHub. Se essa opção não estiver disponível, entre em contato com o mantenedor por um canal privado oficial antes de compartilhar detalhes técnicos.

Sempre que possível, inclua:

- Versão ou commit afetado;
- Descrição da vulnerabilidade e seu possível impacto;
- Passos mínimos para reprodução;
- Evidências sanitizadas, sem informações sensíveis.

**Não envie** tokens de ativação, chaves privadas, credenciais, documentos fiscais ou dados reais de clientes.

## Divulgação responsável

Solicitamos que os detalhes técnicos de vulnerabilidades não corrigidas sejam mantidos em sigilo enquanto são analisados e, quando aplicável, corrigidos.

Os relatos serão avaliados pelo mantenedor conforme a gravidade, a possibilidade de reprodução e o impacto identificado. Esta política não estabelece prazos garantidos de resposta ou correção, nem programa de recompensas (*bug bounty*).

## Escopo

Esta política abrange o código do **PROCEDA Agent** disponibilizado neste repositório.

O **PROCEDA Writer Runtime** e o **License Server** são componentes distintos e não fazem parte do escopo deste repositório.

A disponibilização do código do Agent permite auditoria, mas não constitui certificação de segurança nem garante que uma implantação específica esteja livre de vulnerabilidades. A segurança também depende da configuração e das permissões do ambiente de execução.

## Uso do código-fonte

O código-fonte é disponibilizado para **consulta e auditoria**, sujeito aos termos da licença aplicável ao repositório. A publicação não concede, por si só, permissão para modificação, redistribuição ou uso comercial.

O projeto não aceita contribuições externas via *pull requests* neste momento. **Relatos privados de segurança são bem-vindos.**
