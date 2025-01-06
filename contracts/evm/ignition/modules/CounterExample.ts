import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

const CounterExample = buildModule("CounterExample", (m) => {

  const counterExample = m.contract("CounterExample", [], {
  });

  return { counterExample };
});

export default CounterExample;
