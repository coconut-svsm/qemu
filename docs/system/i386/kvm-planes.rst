KVM planes
==========

KVM planes provide separate privilege levels within one virtual machine.  A
plane has its own virtual CPU state and can be selected as the destination of
device interrupts.  Plane 0 is always present; additional planes require a
host kernel that advertises ``KVM_CAP_PLANES``.

Configuring interrupt delivery
------------------------------

The machine ``device-plane`` property selects the default destination for
device interrupts.  Every QDEV inherits that value unless its ``plane``
property is explicitly set.  For example::

  qemu-system-x86_64 -accel kvm -machine q35,device-plane=1 \
      -device virtio-net-pci,netdev=net0,plane=2 \
      -netdev user,id=net0 \
      -device vfio-pci,host=0000:01:00.0,plane=2

In this example, devices without an override deliver interrupts to plane 1.
The network and assigned PCI devices deliver MSI and MSI-X interrupts to
plane 2.  A plane number must be smaller than the number reported by
``KVM_CAP_PLANES``.  Plane properties cannot be changed after the machine or
device has been realized.

QEMU creates nonzero planes on demand.  They require an in-kernel interrupt
controller.  Emulated PCI MSI writes and KVM IRQFD delivery both retain the
originating device's plane selection, so the property applies to emulated and
assigned devices.

Legacy interrupt limitation
---------------------------

KVM has one GSI routing table shared by all planes.  QEMU installs that table
through the machine's default device plane, so IRQCHIP-routed interrupts such
as PIC, IOAPIC, PIT, RTC, and PCI INTx all target the default plane.  A
per-device override affects MSI and MSI-X delivery, but cannot independently
redirect those legacy interrupts.

Object model and migration
--------------------------

The KVM accelerator exposes a ``kvm-plane`` child named ``plane[N]`` for each
supported plane.  Each plane contains ``kvm-plane-vcpu`` children named
``vcpu[N]`` as KVM requests virtual CPUs for that plane.  Their read-only
``id`` and ``vcpu-id`` properties represent the kernel identifiers and provide
the object-model foundation for future per-plane migration state.

Migration is currently blocked as soon as QEMU creates a nonzero plane.
Plane 0 retains the existing KVM migration behavior.
