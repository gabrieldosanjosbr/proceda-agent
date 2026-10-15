# PROCEDA Agent

O **PROCEDA Agent** é o componente responsável pelo gerenciamento local do licenciamento do PROCEDA Writer.

Executado na infraestrutura do cliente, o Agent realiza a comunicação com o License Server para validar e renovar as autorizações necessárias à execução do Writer.

## Transparência e privacidade

O código-fonte do PROCEDA Agent é disponibilizado publicamente para **consulta e auditoria**, permitindo que clientes e equipes de segurança inspecionem seu funcionamento, identifiquem as informações transmitidas e verifiquem as comunicações externas realizadas.

O PROCEDA Agent não recebe, processa ou transmite o conteúdo dos documentos PROCEDA. Sua finalidade é exclusivamente o gerenciamento do licenciamento.

O processamento dos documentos é realizado localmente pelo PROCEDA Writer, sem necessidade de transmissão de dados comerciais ou fiscais para serviços externos.

O código-fonte do Agent é disponibilizado para fins de auditoria, conforme os termos de sua licença. Sua disponibilização não implica autorização para modificação, redistribuição ou contribuições externas.

## Segurança

Para consultar a política de segurança do PROCEDA Agent ou reportar uma vulnerabilidade, consulte o [SECURITY.md](SECURITY.md).

Vulnerabilidades de segurança devem ser reportadas por canais privados, evitando a divulgação pública antes da análise e eventual correção.