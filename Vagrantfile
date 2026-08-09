# frozen_string_literal: true

require "json"

Vagrant.require_version "= 2.3.4"

project_root = File.expand_path(__dir__)
state_file = File.join(project_root, ".vagrant", "dac-vm.json")
source_archive = File.join(project_root, ".vagrant", "dac-source.tar")

unless File.file?(state_file)
  raise Vagrant::Errors::VagrantError,
        "VM state is missing. Create the controller with scripts/vm-init."
end

vm_state = JSON.parse(File.read(state_file))
required_state = %w[target_ip target_port host_key_fingerprint commit]
missing_state = required_state.reject { |key| vm_state.key?(key) }
unless missing_state.empty?
  raise Vagrant::Errors::VagrantError,
        "VM state is incomplete: missing #{missing_state.join(', ')}"
end

Vagrant.configure("2") do |config|
  config.vm.define "controller", primary: true do |controller|
    controller.vm.box = "debian/bookworm64"
    controller.vm.box_version = "12.20260519.1"
    controller.vm.hostname = "dac-controller"

    # A synchronized project directory would give a compromised guest a write path
    # to the controller host. Source is uploaded once by scripts/vm-init instead.
    controller.vm.synced_folder ".", "/vagrant", disabled: true

    controller.ssh.forward_agent = false
    controller.ssh.forward_x11 = false
    controller.ssh.keys_only = true

    controller.vm.provider :libvirt do |libvirt|
      libvirt.driver = "kvm"
      libvirt.system_uri = "qemu:///system"
      libvirt.cpus = 2
      libvirt.memory = 4096
      libvirt.management_network_mode = "nat"
      libvirt.management_network_guest_ipv6 = "no"
      libvirt.graphics_type = "none"
      libvirt.video_accel3d = false
    end

    if File.file?(source_archive)
      controller.vm.provision "file", source: source_archive, destination: "/tmp/dac-source.tar"
      controller.vm.provision "shell",
                              path: "vm/provision/bootstrap.sh",
                              args: [
                                vm_state.fetch("target_ip"),
                                vm_state.fetch("target_port").to_s,
                                vm_state.fetch("host_key_fingerprint"),
                                vm_state.fetch("commit")
                              ]
    end
  end
end
