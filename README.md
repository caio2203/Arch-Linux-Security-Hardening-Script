# Arch Linux Security Hardening Script

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Shell](https://img.shields.io/badge/shell-bash-green.svg)
![Distro](https://img.shields.io/badge/distro-Arch%20Linux-0f94d2.svg)
![Security](https://img.shields.io/badge/security-hardening-red.svg)

Um script inteligente e adaptativo para hardening de sistemas Arch Linux, oferecendo três níveis de segurança balanceados entre proteção e usabilidade.

## 🎯 Características Principais

- **🛡️ Hardening Adaptativo**: Três perfis de segurança para diferentes necessidades
- **🔄 Reversível**: Backups automáticos antes de qualquer mudança
- **📊 Monitoramento Contínuo**: Script de verificação integrado
- **⚡ Não Intrusivo**: Mantém a usabilidade do sistema
- **🔍 Logs Inteligentes**: Registra apenas eventos relevantes
- **🎨 Interface Amigável**: Menu interativo com cores e feedback claro

## 🚀 Instalação Rápida

```bash
# Clone o repositório
git clone https://github.com/seu-usuario/arch-hardening-script.git
cd arch-hardening-script

# Dar permissão de execução
chmod +x hardening_script.sh

# Executar (NÃO como root)
./hardening_script.sh
```

## 📋 Perfis de Segurança

### 🏠 Perfil 1: Desktop Doméstico
**Recomendado para uso pessoal**
- ✅ Firewall básico (nftables)
- ✅ Atualizações automáticas
- ✅ Parâmetros de kernel essenciais
- ✅ Configurações de usuário seguras
- ✅ Zero impacto na usabilidade
- 🎯 **Protege contra 90% dos ataques comuns**

### 💻 Perfil 2: Workstation de Desenvolvimento
**Ideal para desenvolvedores e usuários avançados**
- ✅ Todas as proteções do Perfil 1
- ✅ Auditoria seletiva (auditd)
- ✅ AppArmor para aplicações web
- ✅ Firewall com regras para desenvolvimento
- ✅ Logging inteligente de eventos críticos
- 🎯 **Segurança avançada sem prejudicar desenvolvimento**

### 🔒 Perfil 3: Sistema Crítico
**Para ambientes de alta segurança**
- ✅ Todas as proteções dos Perfis 1 e 2
- ✅ Monitoramento de integridade (AIDE)
- ✅ Parâmetros de kernel restritivos
- ✅ Auditoria completa otimizada
- ✅ Configurações máximas de sudo
- ⚠️ **Pode impactar performance em sistemas antigos**

## 🛠️ Funcionalidades Implementadas

### 🔥 Firewall (nftables)
- Política padrão de negação
- Regras específicas por perfil
- Logging de tentativas de scan
- Bloqueio de backdoors conhecidos

### 📝 Sistema de Auditoria
- Monitoramento de arquivos críticos
- Rastreamento de escalação de privilégios
- Logs otimizados por perfil
- Detecção de mudanças suspeitas

### 🐧 Hardening do Kernel
- Proteções contra exploits
- ASLR (Address Space Layout Randomization)
- Proteções de rede
- Parâmetros adaptados por perfil

### 🔐 Controle de Acesso
- AppArmor para aplicações críticas
- Configurações sudo restritivas
- Timeouts de sessão
- Políticas de senha

### 📊 Monitoramento
- Script de verificação integrado
- Relatórios de status em tempo real
- Alertas para atividades suspeitas
- Logs estruturados

## 📖 Como Usar

### Execução Inicial
```bash
# Executar o script (como usuário normal)
./hardening_script.sh

# Selecionar perfil no menu interativo
1) Desktop Doméstico
2) Workstation de Desenvolvimento  
3) Sistema Crítico
4) Verificar sistema atual
5) Sair

# Reiniciar após a implementação
sudo reboot
```

### Monitoramento Contínuo
```bash
# Verificação manual do sistema
sudo security-check

# Ou usar o alias criado
sec-check

# Verificação automatizada (opcional)
# Adicionar ao cron para execução diária
echo "0 9 * * * /usr/local/bin/security-check >> /var/log/daily-security.log" | sudo crontab -
```

## 📊 Exemplo de Saída do security-check

```
=== Verificação de Segurança do Sistema ===
Data: Thu Aug 28 15:30:45 2025

--- Status dos Serviços ---
Firewall (nftables): active
SSH: inactive  
Auditd: active
AppArmor: active

--- Configurações de Segurança ---
Perfis AppArmor: 12
Regras de auditoria: 8
Regras do firewall: 4

--- Logs Recentes (últimas 24h) ---
Tentativas de login falhadas: 0
Eventos de sudo: 5

--- Sistema ---
Última atualização: Aug 28 10:15
Uptime: 2 hours, 15 minutes
Load average: 0.25, 0.30, 0.28

=== Fim da Verificação ===
```

## 🔧 Configurações Detalhadas

### Firewall (nftables)
```bash
# Visualizar regras ativas
sudo nft list ruleset

# Status do serviço
sudo systemctl status nftables
```

### Sistema de Auditoria
```bash
# Verificar regras ativas
sudo auditctl -l

# Visualizar logs
sudo ausearch -k users
```

### AppArmor
```bash
# Status dos perfis
sudo aa-status

# Perfis em modo enforce
sudo aa-enforce /usr/bin/firefox
```

## 🚨 Resolução de Problemas

### Problema: Firewall bloqueando aplicações
```bash
# Verificar logs do firewall
sudo journalctl -u nftables

# Adicionar regra temporária
sudo nft add rule inet filter input tcp dport PORTA accept
```

### Problema: SSH não funcionando
```bash
# Verificar configuração
sudo sshd -t

# Reverter configuração
sudo cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
sudo systemctl restart sshd
```

### Problema: AppArmor bloqueando aplicação
```bash
# Colocar perfil em modo complain
sudo aa-complain /caminho/para/aplicacao

# Verificar logs de negação
sudo grep DENIED /var/log/audit/audit.log
```

## 🔄 Como Reverter Mudanças

O script cria backups automáticos em `/tmp/hardening_backup_[timestamp]`. Para reverter:

```bash
# Encontrar o backup mais recente
ls -la /tmp/hardening_backup_*

# Restaurar configurações
sudo cp -r /tmp/hardening_backup_TIMESTAMP/* /

# Reiniciar serviços afetados
sudo systemctl restart nftables sshd auditd
```

## ⚡ Compatibilidade

- **OS**: Arch Linux (testado), Manjaro (compatível)
- **Shell**: Bash, Zsh, Fish
- **Arquitetura**: x86_64, ARM64
- **Kernel**: Linux 5.4+

## 🤝 Contribuindo

Contribuições são muito bem-vindas! Por favor:

1. **Fork** o projeto
2. **Crie** uma branch para sua feature (`git checkout -b feature/nova-feature`)
3. **Commit** suas mudanças (`git commit -am 'Adiciona nova feature'`)
4. **Push** para a branch (`git push origin feature/nova-feature`)
5. **Abra** um Pull Request

### Áreas que Precisam de Contribuição
- [ ] Suporte para outras distribuições baseadas em Arch
- [ ] Perfis customizados por usuário
- [ ] Interface gráfica (GTK/Qt)
- [ ] Integração com ferramentas de SIEM
- [ ] Testes automatizados
- [ ] Documentação em outros idiomas

## 📋 Roadmap

- [x] ✅ Implementação dos três perfis básicos
- [x] ✅ Sistema de backup e recuperação
- [x] ✅ Script de monitoramento
- [ ] 🔄 Interface gráfica
- [ ] 🔄 Perfis customizáveis
- [ ] 🔄 Integração com Lynis
- [ ] 🔄 Suporte a containers
- [ ] 🔄 Alertas por email/telegram

## ⚠️ Aviso Legal

Este script modifica configurações críticas do sistema. Sempre:
- **Faça backup** completo do sistema antes de usar
- **Teste** em ambiente não-produtivo primeiro
- **Leia** o código antes de executar
- **Entenda** as implicações de cada configuração

O autor não se responsabiliza por problemas causados pelo uso inadequado.

## 📄 Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

## 👨‍💻 Autor

Desenvolvido por [<img src="https://github.com/caio2203.png" width="40" height="40" style="border-radius:50%"> @caio2203](https://github.com/caio2203) especialista em Linux e engenheiro de dados

## 🙏 Agradecimentos

- Comunidade Arch Linux
- Projeto AppArmor
- Desenvolvedores do nftables
- Contribuidores do projeto AIDE
- Todos que reportaram bugs e sugeriram melhorias

---

⭐ **Se este script foi útil para você, considere dar uma estrela no projeto!** ⭐

**#ArchLinux #Security #Hardening #CyberSecurity #Linux #OpenSource**
