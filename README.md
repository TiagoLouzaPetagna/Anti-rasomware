# Anti Ramsomware Para LINUX- Não Finalizado
Consiste na observação de pastas especifícas e honeypots pela biblioteca watchdog, a cada alteração de arquivo chama o ausearch, configurado pelo auditd para observar a pasta, buscando o nome do arquivo alterado e filtrando pelas syscalls mas utilizadas por ramsomwares

### Syscalls
`openat()`
`rename()`
`write()`
`unlink()`
`stat()`

A cada 10 alterações em 30 segundos, com essas syscalls pelo mesmo pid nas pastas observadas, o programa calcula a entropia dos arquivos criados para verificar se houve criptografia.
O programa tenta finalizar primeiro pelo ppid. Verificando antes se esta na white-list={"systemd", "init", "bash", "zsh", "sh", "sshd",
    "cron", "crond", "dbus-daemon", "NetworkManager",
    "agetty", "login", "Xorg", "gnome-shell", "kdeinit"}
Se não puder finalizar pelo ppid tenta finalizar pelo pid, e coloca o arquivo do programa de execução em quarentena.


#### Limpeza de logs

`1- A cada verficação de modificação que realmente chama uma das syscalls passa para outro log e adiciona no contador de alterações perigosas.`
`2- A cada 30 segundos o log principal que é verificado a cada chamada é limpo.`
`3- O segundo log com as alterações perigosas é visualizado de 8 em 8 minutos`
