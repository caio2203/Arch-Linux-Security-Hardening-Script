#!/bin/bash

# Script de Hardening Inteligente para Arch Linux
# Autor: Especialista em Cibersegurança Linux
# Versão: 1.0
# Data: 2025

set -euo pipefail

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Função de logging
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Verificar se é executado como root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        error "Este script não deve ser executado como root"
        error "Use: ./hardening_script.sh"
        exit 1
    fi
}

# Verificar se é Arch Linux
check_arch() {
    if ! grep -q "Arch Linux" /etc/os-release; then
        error "Este script é específico para Arch Linux"
        exit 1
    fi
}

# Backup de configurações existentes
create_backup() {
    local backup_dir="/tmp/hardening_backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    log "Criando backup das configurações atuais em: $backup_dir"
    
    # Backup de arquivos críticos
    sudo cp -r /etc/nftables.conf "$backup_dir/" 2>/dev/null || true
    sudo cp -r /etc/ssh/sshd_config "$backup_dir/" 2>/dev/null || true
    sudo cp -r /etc/sysctl.d/ "$backup_dir/" 2>/dev/null || true
    sudo cp -r /etc/audit/ "$backup_dir/" 2>/dev/null || true
    
    echo "$backup_dir" > /tmp/last_hardening_backup
    info "Backup salvo. Para reverter: sudo cp -r $backup_dir/* /"
}

# Perfil 1: Desktop Doméstico
apply_home_desktop() {
    log "Aplicando configuração para Desktop Doméstico..."
    
    # 1. Atualizações automáticas
    log "Configurando atualizações automáticas..."
    sudo pacman -S --noconfirm --needed pacman-contrib
    
    # Hook para limpeza de cache
    sudo mkdir -p /etc/pacman.d/hooks
    sudo tee /etc/pacman.d/hooks/clean_cache.hook > /dev/null << 'EOF'
[Trigger]
Operation = Upgrade
Operation = Install
Operation = Remove
Type = Package
Target = *

[Action]
Description = Cleaning pacman cache...
When = PostTransaction
Exec = /usr/bin/paccache -rk3
EOF

    # 2. Firewall básico
    log "Configurando firewall básico..."
    sudo pacman -S --noconfirm --needed nftables
    
    sudo tee /etc/nftables.conf > /dev/null << 'EOF'
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        
        # Loopback sempre permitido
        iif lo accept
        
        # Conexões estabelecidas
        ct state established,related accept
        
        # ICMP básico
        ip protocol icmp accept
        ip6 nexthdr ipv6-icmp accept
        
        # Log tentativas de scan
        tcp dport { 22, 23, 135, 445, 3389 } limit rate 3/minute log prefix "scan_detected: "
    }
    
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
    
    chain output {
        type filter hook output priority 0; policy accept;
    }
}
EOF

    sudo systemctl enable nftables
    sudo systemctl start nftables

    # 3. Parâmetros de kernel básicos
    log "Configurando parâmetros de kernel básicos..."
    sudo tee /etc/sysctl.d/50-security-basic.conf > /dev/null << 'EOF'
# Proteções básicas essenciais
kernel.dmesg_restrict = 1
kernel.randomize_va_space = 2

# Proteções de rede básicas
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
EOF

    sudo sysctl -p /etc/sysctl.d/50-security-basic.conf

    # 4. Configurações de usuário básicas
    log "Configurando políticas de usuário..."
    echo "TMOUT=1800" | sudo tee -a /etc/profile > /dev/null
    echo "umask 022" | sudo tee -a /etc/profile > /dev/null

    info "Configuração Desktop Doméstico aplicada com sucesso!"
}

# Perfil 2: Workstation de Desenvolvimento
apply_dev_workstation() {
    log "Aplicando configuração para Workstation de Desenvolvimento..."
    
    # Aplicar configurações básicas primeiro
    apply_home_desktop
    
    # Configurações adicionais para desenvolvimento
    log "Adicionando configurações de desenvolvimento..."
    
    # 1. Auditoria seletiva
    log "Configurando auditoria seletiva..."
    sudo pacman -S --noconfirm --needed audit
    
    sudo tee /etc/audit/rules.d/dev-security.rules > /dev/null << 'EOF'
# Buffer moderado
-b 4096

# Falha = warning apenas
-f 1

# Monitorar mudanças críticas
-w /etc/passwd -p wa -k users
-w /etc/shadow -p wa -k users
-w /etc/sudoers -p wa -k sudo
-w /etc/ssh/sshd_config -p wa -k ssh

# Monitorar escalação de privilégios
-a always,exit -F arch=b64 -S execve -F path=/bin/su -k privilege_escalation
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/sudo -k privilege_escalation

# Monitorar modificações de sistema
-w /boot -p wa -k boot_changes
EOF

    sudo systemctl enable auditd
    sudo systemctl start auditd

    # 2. AppArmor para aplicações web
    log "Configurando AppArmor..."
    sudo pacman -S --noconfirm --needed apparmor apparmor-utils
    
    # Adicionar ao kernel
    sudo sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="/&apparmor=1 security=apparmor /' /etc/default/grub
    sudo grub-mkconfig -o /boot/grub/grub.cfg
    
    sudo systemctl enable apparmor

    # 3. Firewall mais específico para desenvolvimento
    sudo tee /etc/nftables.conf > /dev/null << 'EOF'
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        
        iif lo accept
        ct state established,related accept
        
        ip protocol icmp accept
        ip6 nexthdr ipv6-icmp accept
        
        # Permitir desenvolvimento local
        tcp dport { 3000, 8000, 8080, 8443 } ip saddr 127.0.0.1 accept
        
        # Log tentativas suspeitas
        tcp dport { 22, 23, 135, 445, 1433, 3389 } limit rate 2/minute log prefix "dev_scan: "
    }
    
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
    
    chain output {
        type filter hook output priority 0; policy accept;
        
        # Bloquear backdoors conhecidos
        tcp dport { 4444, 5555, 6666, 1234 } log prefix "backdoor_block: " drop
    }
}
EOF

    sudo systemctl restart nftables

    # 4. Parâmetros de kernel para desenvolvimento
    sudo tee /etc/sysctl.d/60-dev-security.conf > /dev/null << 'EOF'
# Parâmetros adicionais para desenvolvimento
kernel.kptr_restrict = 1
kernel.yama.ptrace_scope = 1

# Limites para prevenir fork bombs
kernel.pid_max = 32768

# Proteções de rede adicionais
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
EOF

    sudo sysctl -p /etc/sysctl.d/60-dev-security.conf

    # 5. Configurações de sudo mais restritivas
    sudo tee /etc/sudoers.d/dev-security > /dev/null << 'EOF'
# Log comandos sudo
Defaults logfile="/var/log/sudo.log"
Defaults timestamp_timeout=15
Defaults passwd_tries=3
EOF

    info "Configuração Workstation de Desenvolvimento aplicada!"
}

# Perfil 3: Sistema Crítico
apply_critical_system() {
    log "Aplicando configuração para Sistema Crítico..."
    
    # Aplicar configurações de desenvolvimento primeiro
    apply_dev_workstation
    
    # Configurações críticas adicionais
    log "Adicionando configurações críticas..."
    
    # 1. Auditoria completa mas otimizada
    sudo tee /etc/audit/rules.d/critical-security.rules > /dev/null << 'EOF'
# Buffer grande para alta atividade
-b 8192

# Falha crítica mas não trava sistema
-f 1

# Monitoramento completo de identidade
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k identity

# Monitorar todas as configurações críticas
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /etc/nftables.conf -p wa -k firewall
-w /boot -p wa -k boot
-w /etc/apparmor -p wa -k apparmor

# Monitorar execuções privilegiadas
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_commands
-a always,exit -F arch=b32 -S execve -F euid=0 -k root_commands

# Monitorar mudanças de permissões
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod

# Monitorar acesso a arquivos sensíveis
-w /var/log/auth.log -p rwa -k auth_log
-w /var/log/sudo.log -p rwa -k sudo_log
EOF

    sudo systemctl restart auditd

    # 2. AIDE para monitoramento de integridade
    if yay -Qi aide &>/dev/null || paru -Qi aide &>/dev/null; then
        log "Configurando AIDE para monitoramento de integridade..."
        
        sudo tee /etc/aide.conf > /dev/null << 'EOF'
@@define DBDIR /var/lib/aide
@@define LOGDIR /var/log/aide

database=file:@@{DBDIR}/aide.db.gz
database_out=file:@@{DBDIR}/aide.db.new.gz
gzip_dbout=yes

# Monitorar diretórios críticos
/boot NORMAL
/etc NORMAL
/bin NORMAL
/sbin NORMAL
/usr/bin NORMAL
/usr/sbin NORMAL
/lib NORMAL
/lib64 NORMAL

# Excluir diretórios dinâmicos
!/var/log/.*
!/var/cache/.*
!/var/spool/.*
!/tmp/.*
!/proc/.*
!/sys/.*
!/dev/.*
!/home/.*/\.cache/.*
!/home/.*/\.mozilla/.*
EOF

        # Inicializar AIDE
        sudo aide --init
        sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

        # Script de verificação semanal
        sudo tee /etc/cron.weekly/aide > /dev/null << 'EOF'
#!/bin/bash
/usr/bin/aide --check 2>&1 | /usr/bin/logger -t aide
if [ $? -ne 0 ]; then
    echo "AIDE detected changes! Check /var/log/aide/" | mail -s "AIDE Alert" root
fi
EOF
        sudo chmod +x /etc/cron.weekly/aide
    else
        warn "AIDE não instalado. Instale com: yay -S aide"
    fi

    # 3. Parâmetros de kernel mais restritivos
    sudo tee /etc/sysctl.d/70-critical-security.conf > /dev/null << 'EOF'
# Proteções avançadas contra exploits
kernel.kptr_restrict = 2
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# Proteção máxima de memória
kernel.yama.ptrace_scope = 2

# Limites rigorosos
kernel.pid_max = 65536
fs.suid_dumpable = 0

# Proteções de rede máximas
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_timestamps = 0
EOF

    sudo sysctl -p /etc/sysctl.d/70-critical-security.conf

    # 4. Configurações sudo críticas
    sudo tee /etc/sudoers.d/critical-security > /dev/null << 'EOF'
# Log completo de sudo
Defaults log_input, log_output
Defaults logfile="/var/log/sudo.log"
Defaults timestamp_timeout=0
Defaults passwd_tries=2
Defaults badpass_message="Acesso negado. Tentativa registrada."
Defaults requiretty
EOF

    info "Configuração Sistema Crítico aplicada!"
}

# Configurar SSH se existir
configure_ssh() {
    if systemctl is-enabled sshd &>/dev/null || [ -f /etc/ssh/sshd_config ]; then
        log "Configurando hardening do SSH..."
        
        sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
        
        sudo tee /etc/ssh/sshd_config > /dev/null << 'EOF'
# Porta padrão (altere se necessário)
Port 22

# Protocolo apenas v2
Protocol 2

# Configurações de autenticação
PasswordAuthentication yes
PermitEmptyPasswords no
PubkeyAuthentication yes

# Configurações de acesso
PermitRootLogin no
MaxAuthTries 3
MaxStartups 10:30:60
LoginGraceTime 30

# Algoritmos seguros
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512

# Recursos desnecessários desabilitados
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PermitTunnel no
EOF

        sudo systemctl restart sshd
        info "SSH configurado com segurança"
    else
        info "SSH não detectado - configuração pulada"
    fi
}

# Script de verificação do sistema
create_security_check() {
    log "Criando script de verificação de segurança..."
    
    sudo tee /usr/local/bin/security-check > /dev/null << 'EOF'
#!/bin/bash

echo "=== Verificação de Segurança do Sistema ==="
echo "Data: $(date)"
echo

echo "--- Status dos Serviços ---"
echo "Firewall (nftables): $(systemctl is-active nftables 2>/dev/null || echo 'inactive')"
echo "SSH: $(systemctl is-active sshd 2>/dev/null || echo 'inactive')"
echo "Auditd: $(systemctl is-active auditd 2>/dev/null || echo 'inactive')"
echo "AppArmor: $(systemctl is-active apparmor 2>/dev/null || echo 'inactive')"

echo
echo "--- Configurações de Segurança ---"
echo "Perfis AppArmor: $(aa-status --enabled 2>/dev/null | wc -l || echo 'N/A')"
echo "Regras de auditoria: $(auditctl -l 2>/dev/null | wc -l || echo 'N/A')"
echo "Regras do firewall: $(nft list ruleset 2>/dev/null | grep -c 'chain' || echo 'N/A')"

echo
echo "--- Logs Recentes (últimas 24h) ---"
echo "Tentativas de login falhadas: $(journalctl --since '1 day ago' | grep -c 'Failed password' || echo '0')"
echo "Eventos de sudo: $(journalctl --since '1 day ago' | grep -c 'sudo:' || echo '0')"

echo
echo "--- Sistema ---"
echo "Última atualização: $(ls -la /var/log/pacman.log | awk '{print $6, $7, $8}')"
echo "Uptime: $(uptime -p)"
echo "Load average: $(uptime | awk -F'load average:' '{print $2}')"

echo
echo "=== Fim da Verificação ==="
EOF

    sudo chmod +x /usr/local/bin/security-check
    
    # Criar alias para facilitar uso
    echo "alias sec-check='sudo security-check'" >> ~/.bashrc
    
    info "Script de verificação criado: /usr/local/bin/security-check"
    info "Use: security-check ou sec-check"
}

# Menu principal
show_menu() {
    clear
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║            Script de Hardening Inteligente                  ║"
    echo "║                    Arch Linux                                ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo
    echo -e "${GREEN}Selecione o perfil de segurança apropriado:${NC}"
    echo
    echo -e "${YELLOW}1)${NC} Desktop Doméstico"
    echo "   • Proteções básicas essenciais"
    echo "   • Impacto mínimo na usabilidade" 
    echo "   • Firewall simples + atualizações"
    echo
    echo -e "${YELLOW}2)${NC} Workstation de Desenvolvimento"
    echo "   • Proteções intermediárias"
    echo "   • Auditoria seletiva"
    echo "   • AppArmor para aplicações web"
    echo "   • Configurações para desenvolvimento"
    echo
    echo -e "${YELLOW}3)${NC} Sistema Crítico"
    echo "   • Máxima segurança"
    echo "   • Monitoramento completo"
    echo "   • Todas as proteções ativadas"
    echo "   • Pode impactar performance"
    echo
    echo -e "${YELLOW}4)${NC} Apenas verificar sistema atual"
    echo
    echo -e "${YELLOW}5)${NC} Sair"
    echo
}

# Função principal
main() {
    check_root
    check_arch
    
    while true; do
        show_menu
        read -p "Digite sua opção [1-5]: " choice
        
        case $choice in
            1)
                create_backup
                apply_home_desktop
                configure_ssh
                create_security_check
                log "Hardening Desktop Doméstico concluído!"
                echo -e "\n${GREEN}Reinicie o sistema para aplicar todas as configurações.${NC}"
                break
                ;;
            2)
                create_backup
                apply_dev_workstation
                configure_ssh
                create_security_check
                log "Hardening Workstation de Desenvolvimento concluído!"
                echo -e "\n${GREEN}Reinicie o sistema para aplicar todas as configurações.${NC}"
                break
                ;;
            3)
                create_backup
                apply_critical_system
                configure_ssh
                create_security_check
                log "Hardening Sistema Crítico concluído!"
                echo -e "\n${GREEN}Reinicie o sistema para aplicar todas as configurações.${NC}"
                break
                ;;
            4)
                if [ -f /usr/local/bin/security-check ]; then
                    sudo /usr/local/bin/security-check
                else
                    error "Script de verificação não encontrado. Execute uma configuração primeiro."
                fi
                echo
                read -p "Pressione Enter para continuar..."
                ;;
            5)
                info "Saindo..."
                exit 0
                ;;
            *)
                error "Opção inválida. Tente novamente."
                sleep 2
                ;;
        esac
    done
}

# Verificação de dependências
check_dependencies() {
    local deps=("sudo" "systemctl" "nft")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [ ${#missing[@]} -ne 0 ]; then
        error "Dependências faltando: ${missing[*]}"
        error "Instale com: sudo pacman -S ${missing[*]}"
        exit 1
    fi
}

# Executar script
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    check_dependencies
    main "$@"
fi