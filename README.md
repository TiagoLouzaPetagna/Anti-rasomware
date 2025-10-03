## CyberRaiders – Monitor de Ransomware para Linux

Projeto do Challenge FIAP, grupo CyberRaiders. Sistema de monitoramento e defesa contra ransomwares em Linux.
Ele combina honeypots, monitoramento em tempo real de arquivos, análise de entropia e quarentena automática de executáveis suspeitos.
Inclui interface gráfica

## Rodar o Programa

Para rodar a solução precisa rodar o arquivo elf "CyberRaiders", escolher as pastas a serem monitoradas na aba Pastas/Controles (de preferência não usar pastas amplas como /, /home, /etc); e depois de escolher as pastas iniciar o programa clicando na botão na parte inferior da interface gráfica. Para parar de rodar apenas clique no botão de parar monitoramento à direita do botão de iniciar.


### Funcionalidades

-Criação de arquivos honeypot em pastas críticas e selecionadas pelo usuário (Documents, Desktop, Downloads), que são criados ao iniciar o programa e apagadas ao encerrar o programa.

-Monitoramento em tempo real de eventos do sistema de arquivos com watchdog e syscalls via auditd.

-Análise de entropia dos arquivos modificados para identificar possíveis criptografias.

-Detecção de processos suspeitos que alteram muitos arquivos em pouco tempo.

-Colocação em quarentena de executáveis suspeitos e encerramento automático do processo.

-Interface CLI simples para servidores e GUI em PyQt5 para desktops.

-Logs detalhados de alterações, processos finalizados e arquivos analisados.

-Configuração automática do auditd em distribuições Linux suportadas.

## Funcionalidades na GUI:

-Aba Logs: exibe eventos e alertas.

-Aba Processos: mostra PIDs monitorados, alterações e status.

-Aba Arquivos Modificados: lista arquivos afetados, PID e status (normal, modificado, suspeito).

-Aba Pastas/Controle: permite adicionar, remover e limpar pastas monitoradas.

-Botões Iniciar/Parar monitoramento.

-Clique duplo em um processo para filtrar arquivos relacionados.

## Estratégia de Detecção

### 1- Watchdog monitora mudanças em arquivos em pastas selecionadas pelo usuario.

### 2- A cada modificação é buscado o pid, ppid, comm e nome atual do arquivo (caso tenha sido modificado). A modificação só vista se caso chamar uma das seguintes syscalls:
#### Syscalls
`openat()`
`rename()`
`write()`
`unlink()`
`stat()`
`creat()`
`openat2()`
`writev()`

### 3- Arquivos modificados são avaliados:

- Se muitos arquivos foram alterados em sequência.

- Se a entropia > 7.6 (indicativo de criptografia).

- Se não forem arquivos legítimos (ZIP, PDF).

- Caso suspeito: processo encerrado + executável movido para quarentena.

A cada 10 alterações, com essas syscalls pelo mesmo pid nas pastas observadas, o programa calcula a entropia dos arquivos criados para verificar se houve criptografia.
O programa busca primeiro no /proc o executavel resposavel por tal pid e coloca no /var/quarentena_execs
Depois da quarentena o programa é encerrado pelo seu pid e colocado um popup na tela avisando do arquivo encerrado


#### Limpeza de logs

`O Log do audit tem configuração de rotação entre dois arquivos e um limite máximo de tamanho.`
