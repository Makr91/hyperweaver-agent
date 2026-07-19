// Emits every UTM virtual machine as JSON [{UUID, Name, Status}] — the
// scripting-API list (utmctl's list output parses worse).
function run() {
  const utm = Application('UTM');
  const machines = [];
  for (const vm of utm.virtualMachines()) {
    machines.push({ UUID: vm.id(), Name: vm.name(), Status: vm.status() });
  }
  return JSON.stringify(machines);
}
