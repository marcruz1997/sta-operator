# Auditoria: OpenShift Logging e LokiStack

A aba **Auditoria de usuários** do painel lê os logs de auditoria do cluster a partir do LokiStack. Sem ele, a aba mostra "Instale o OpenShift Logging (LokiStack): o painel se conecta sozinho" e o resto do painel funciona normalmente.

> Ferramenta não oficial, sem suporte da Red Hat. Os passos abaixo seguem a documentação do OpenShift Logging, que pode mudar entre versões. Confira a versão do seu cluster.

## 1. Instalar o OpenShift Logging e o LokiStack

Pelo console, em **Operators → OperatorHub**:

1. Instale o **Loki Operator** (namespace `openshift-operators-redhat`, ou o que o console sugerir).
2. Instale o **Red Hat OpenShift Logging** (namespace `openshift-logging`).
3. Crie um `LokiStack` no namespace `openshift-logging`, com o tamanho adequado ao seu cluster e um `StorageClass` com PVCs.
4. Crie um `ClusterLogForwarder` ou use o `ClusterLogging` padrão para que os logs de auditoria cheguem ao LokiStack.

## 2. Confirmar o gateway

O STA usa o serviço do gateway do LokiStack:

```
oc get svc -n openshift-logging | grep gateway
```

Deve aparecer `logging-loki-gateway-http` na porta `8080`.

## 3. Como o STA se conecta

O operator procura esse serviço sozinho a cada 5 minutos e configura o painel com a URL:

```
https://logging-loki-gateway-http.openshift-logging.svc:8080/api/logs/v1/audit
```

Não é preciso configurar nada manualmente. Se o serviço for instalado depois, o painel passa a ler a auditoria dentro de alguns minutos.

## 4. Permissões

O painel precisa ler os logs de auditoria. O operator já concede isso à conta de serviço do painel (`breakglass-portal`), com o acesso `loki.grafana.com` `audit`/`logs` e o caminho `/api/logs/v1/audit/*`.

## Verificação

1. Abra o painel e vá até **Auditoria de usuários**.
2. Escolha um período e um usuário e clique em **Pesquisar**.
3. Se aparecer "Nenhum comando no período", a conexão funciona e não há comandos registrados.
4. Se aparecer erro de certificado, de autorização ou de tempo esgotado, veja o log do painel:

```
oc logs -n breakglass-system deploy/breakglass-panel -c app --tail=60
```

## Desempenho

A consulta cobre 1 hora por padrão e só é feita sob demanda, depois de clicar em **Pesquisar**. Janelas muito longas podem demorar. Se a consulta der tempo esgotado, reduza o período.
