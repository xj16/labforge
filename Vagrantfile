# -*- mode: ruby -*-
# vi: set ft=ruby :
#
# labforge — One-command reproducible security homelab
# https://github.com/xj16/labforge
#
# This Vagrantfile stands up an ISOLATED, host-only, no-internet pentest lab:
#
#   attacker  10.20.0.10   Kali Linux           (Metasploit, Wireshark, Burp)
#   siem      10.20.0.20   Splunk-style SIEM     (centralized log collection)
#   juice     10.20.0.31   OWASP Juice Shop      (deliberately vulnerable)
#   dvwa      10.20.0.32   DVWA                   (deliberately vulnerable)
#   victim    10.20.0.40   Windows 10 victim      (optional, opt-in)
#   deb       10.20.0.51   Debian 12  fleet node
#   ubuntu    10.20.0.52   Ubuntu 22.04 fleet node
#   fedora    10.20.0.53   Fedora 39   fleet node
#   arch      10.20.0.54   Arch Linux  fleet node
#
# EVERY machine is attached to a single VirtualBox host-only network
# (virtualbox__intnet is deliberately NOT used so you can sniff from the host,
# but NAT is disabled on lab NICs — targets have NO route to the internet).
#
# See README.md for the full ethics/legal note. Use only on machines you own.

require "yaml"

# ---------------------------------------------------------------------------
# Configuration is data-driven from lab.yml so the topology is easy to edit
# without touching Ruby. Fall back to sane defaults if the file is missing.
# ---------------------------------------------------------------------------
LAB_CONFIG_FILE = File.join(File.dirname(__FILE__), "lab.yml")

DEFAULT_CONFIG = {
  "network" => {
    "subnet"  => "10.20.0.0",
    "netmask" => "255.255.255.0",
    "prefix"  => "10.20.0",
  },
  "defaults" => {
    "cpus"   => 2,
    "memory" => 1024,
  },
}.freeze

def load_config
  return DEFAULT_CONFIG unless File.exist?(LAB_CONFIG_FILE)
  user = YAML.load_file(LAB_CONFIG_FILE) || {}
  DEFAULT_CONFIG.merge(user) do |_key, default_val, user_val|
    if default_val.is_a?(Hash) && user_val.is_a?(Hash)
      default_val.merge(user_val)
    else
      user_val
    end
  end
end

CONFIG = load_config
PREFIX = CONFIG.dig("network", "prefix")
NETMASK = CONFIG.dig("network", "netmask")

# Environment toggles let you opt into the heavier / licensed boxes.
#   LABFORGE_WINDOWS=1   include the Windows 10 victim (needs a Windows box)
#   LABFORGE_FLEET=1     include the multi-distro fleet (deb/ubuntu/fedora/arch)
#   LABFORGE_MINIMAL=1   only attacker + siem + juice (fast smoke lab)
INCLUDE_WINDOWS = ENV.fetch("LABFORGE_WINDOWS", "0") == "1"
INCLUDE_FLEET   = ENV.fetch("LABFORGE_FLEET", "1") == "1"
MINIMAL         = ENV.fetch("LABFORGE_MINIMAL", "0") == "1"

# ---------------------------------------------------------------------------
# Machine catalogue. Each entry:
#   :name     Vagrant machine name (and Ansible inventory host)
#   :box      Vagrant box slug (all community, freely downloadable)
#   :ip       host-only IP (last octet)
#   :group    Ansible group used to pick provisioning roles
#   :mem/:cpu resource overrides
#   :gui      launch with a GUI window (attacker/victim benefit from this)
# ---------------------------------------------------------------------------
def machines
  list = []

  # --- Attacker ------------------------------------------------------------
  list << {
    name:  "attacker",
    box:   "kalilinux/rolling",
    ip:    10,
    group: "attackers",
    mem:   4096,
    cpu:   2,
    gui:   true,
  }

  # --- SIEM / centralized logging -----------------------------------------
  list << {
    name:  "siem",
    box:   "bento/ubuntu-22.04",
    ip:    20,
    group: "siem",
    mem:   3072,
    cpu:   2,
  }

  # --- Deliberately vulnerable web targets --------------------------------
  list << {
    name:  "juice",
    box:   "bento/ubuntu-22.04",
    ip:    31,
    group: "targets_web",
    mem:   1536,
    cpu:   1,
  }

  unless MINIMAL
    list << {
      name:  "dvwa",
      box:   "bento/debian-12",
      ip:    32,
      group: "targets_web",
      mem:   1024,
      cpu:   1,
    }
  end

  return list if MINIMAL

  # --- Multi-distro fleet --------------------------------------------------
  if INCLUDE_FLEET
    list << { name: "deb",    box: "bento/debian-12",   ip: 51, group: "fleet", mem: 768, cpu: 1 }
    list << { name: "ubuntu", box: "bento/ubuntu-22.04", ip: 52, group: "fleet", mem: 768, cpu: 1 }
    list << { name: "fedora", box: "bento/fedora-39",    ip: 53, group: "fleet", mem: 768, cpu: 1 }
    list << { name: "arch",   box: "archlinux/archlinux", ip: 54, group: "fleet", mem: 768, cpu: 1 }
  end

  # --- Windows victim (opt-in) --------------------------------------------
  if INCLUDE_WINDOWS
    list << {
      name:    "victim",
      box:     "gusztavvargadr/windows-10",
      ip:      40,
      group:   "targets_windows",
      mem:     4096,
      cpu:     2,
      gui:     true,
      windows: true,
    }
  end

  list
end

# ---------------------------------------------------------------------------
# Build the Ansible inventory groups from the machine catalogue so the groups
# stay in lock-step with the topology. Composite groups (log_clients, linux)
# mirror ansible/inventory/hosts.ini.
# ---------------------------------------------------------------------------
def ansible_groups(all_machines)
  by_group = Hash.new { |h, k| h[k] = [] }
  all_machines.each { |m| by_group[m[:group]] << m[:name] }

  linux_groups = %w[attackers siem targets_web fleet]
  log_client_groups = %w[attackers targets_web fleet]

  groups = {}
  by_group.each { |g, names| groups[g] = names }

  # Composite children groups.
  groups["linux:children"]       = linux_groups.select { |g| by_group.key?(g) }
  groups["log_clients:children"] = log_client_groups.select { |g| by_group.key?(g) }

  groups
end

# Per-host vars that drive the web-target role toggles in ansible/site.yml.
# Passed to Vagrant's ansible provisioner via ansible.host_vars.
def ansible_host_vars(all_machines)
  hv = {}
  names = all_machines.map { |m| m[:name] }
  hv["juice"] = { "juiceshop" => true } if names.include?("juice")
  hv["dvwa"]  = { "dvwa" => true }      if names.include?("dvwa")
  hv
end

Vagrant.configure("2") do |config|
  # No box auto-update chatter; keeps the lab reproducible/offline-friendly.
  config.vm.box_check_update = false

  # Disable the default synced folder everywhere — the lab is meant to be
  # isolated, and rsync/vboxsf on a Kali box is a common source of breakage.
  config.vm.synced_folder ".", "/vagrant", disabled: true

  all = machines

  all.each_with_index do |m, index|
    config.vm.define m[:name], primary: (m[:name] == "attacker") do |node|
      node.vm.box = m[:box]
      node.vm.hostname = m[:name] unless m[:windows] # Windows hostnames set via provisioner

      ip_addr = "#{PREFIX}.#{m[:ip]}"

      # Single host-only adapter. No NAT forwarding of lab services to the host.
      node.vm.network "private_network",
                      ip: ip_addr,
                      netmask: NETMASK,
                      virtualbox__intnet: false

      node.vm.provider "virtualbox" do |vb|
        vb.name   = "labforge-#{m[:name]}"
        vb.memory = m[:mem] || CONFIG.dig("defaults", "memory")
        vb.cpus   = m[:cpu] || CONFIG.dig("defaults", "cpus")
        vb.gui    = m.fetch(:gui, false)

        # Harden the VM a little and make networking predictable.
        vb.customize ["modifyvm", :id, "--nictype1", "virtio"]
        vb.customize ["modifyvm", :id, "--nictype2", "virtio"]
        vb.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
        # Promiscuous mode on the host-only NIC so the attacker can sniff the
        # whole lab segment in Wireshark. "allow-all" == capture everything.
        vb.customize ["modifyvm", :id, "--nicpromisc2", "allow-all"]
      end

      # -------------------------------------------------------------------
      # Provisioning
      # -------------------------------------------------------------------
      if m[:windows]
        node.vm.communicator = "winrm"
        node.winrm.username = "vagrant"
        node.winrm.password = "vagrant"
        node.vm.guest = :windows
        node.vm.provision "shell",
                          path: "windows/provision-victim.ps1",
                          args: ["-SiemIp", "#{PREFIX}.20"]
      else
        # Bootstrap Python (Ansible needs it) then hand off to Ansible.
        node.vm.provision "shell",
                          path: "scripts/bootstrap.sh",
                          env: { "LABFORGE_GROUP" => m[:group] }

        # Run Ansible from the host once, on the LAST machine to come up, so a
        # single control node drives the whole fleet (mirrors real IaC
        # pipelines and guarantees the SIEM exists before clients forward).
        #
        # We let Vagrant AUTO-GENERATE the inventory (so per-box SSH ports/keys
        # are correct) and layer our inventory groups on top via ansible.groups.
        # The static ansible/inventory/hosts.ini is for running Ansible by hand
        # against an already-up lab; Vagrant uses its own generated one here.
        if index == all.length - 1
          node.vm.provision "ansible" do |ansible|
            ansible.playbook           = "ansible/site.yml"
            ansible.compatibility_mode = "2.0"
            ansible.limit              = "all"
            ansible.raw_arguments      = ["--diff"]
            ansible.groups             = ansible_groups(all)
            ansible.host_vars          = ansible_host_vars(all)
          end
        end
      end
    end
  end
end
