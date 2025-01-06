import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { expect } from "chai";
import { time } from "@nomicfoundation/hardhat-network-helpers";
import hre from "hardhat";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

// Helper function to create a valid signature for authorization
async function createAuthorizationSignature(
  agent: SignerWithAddress,
  principal: string,
  functionSelector: string,
  startTime: number,
  endTime: number,
  allowedCalls: number
): Promise<string> {
  const messageHash = hre.ethers.solidityPackedKeccak256(
    ["address", "bytes4", "uint256", "uint256", "uint256"],
    [principal, functionSelector, startTime, endTime, allowedCalls]
  );
  return await agent.signMessage(hre.ethers.toBeArray(messageHash));
}

describe("CounterExample", function() {
  async function deployFixture() {
    const [owner, agent, unauthorizedAgent, anotherAgent] = await hre.ethers.getSigners();
    const Counter = await hre.ethers.getContractFactory("CounterExample");
    const counter = await Counter.deploy();

    const incrementFunctionHash = hre.ethers.id("incrementMyCounter()").slice(0, 10);
    const currentTime = await time.latest();

    // Create a signature for initial authorization
    const signature = await createAuthorizationSignature(
      agent,
      owner.address,
      incrementFunctionHash,
      currentTime,
      currentTime + 3600,
      10
    );

    await counter.authorizeAgent(
      agent.address,
      incrementFunctionHash,
      currentTime,
      currentTime + 3600, // 1 hour from now
      10, // usage allowance
      signature
    );

    return { counter, owner, agent, unauthorizedAgent, anotherAgent };
  }

  describe("Basic Counter Operations", function() {
    it("should initialize counter to zero", async function() {
      const { counter, owner } = await loadFixture(deployFixture);
      expect(await counter.getCounter(owner.address)).to.equal(0);
    });

    it("should allow the owner to increment their counter", async function() {
      const { counter, owner } = await loadFixture(deployFixture);
      await counter.connect(owner).incrementMyCounter();
      expect(await counter.getCounter(owner.address)).to.equal(1);
    });

    it("should allow the owner to reset their counter", async function() {
      const { counter, owner } = await loadFixture(deployFixture);
      await counter.connect(owner).incrementMyCounter();
      await counter.connect(owner).resetMyCounter();
      expect(await counter.getCounter(owner.address)).to.equal(0);
    });
  });

  describe("Agent Authorization", function() {
    it("should allow an authorized agent to increment the owner's counter", async function() {
      const { counter, owner, agent } = await loadFixture(deployFixture);
      await counter.connect(agent).incrementMyCounter();
      expect(await counter.getCounter(owner.address)).to.equal(1);
    });

    it("should increment their own counter when an unregistered agent calls incrementMyCounter", async function() {
      const { counter, owner, unauthorizedAgent } = await loadFixture(deployFixture);

      expect(await counter.getCounter(unauthorizedAgent.address)).to.equal(0);
      await counter.connect(unauthorizedAgent).incrementMyCounter();
      expect(await counter.getCounter(unauthorizedAgent.address)).to.equal(1);
      expect(await counter.getCounter(owner.address)).to.equal(0);
    });

    it("should not allow an agent to reset the owner's counter", async function() {
      const { counter, agent } = await loadFixture(deployFixture);
      await expect(counter.connect(agent).resetMyCounter()).to.be.revertedWith(
        "Only principal can reset counter"
      );
    });

    it("should respect usage allowance for agent", async function() {
      const { counter, owner, agent } = await loadFixture(deployFixture);
      const incrementFunctionHash = hre.ethers.id("incrementMyCounter()").slice(0, 10);
      const currentTime = await time.latest();

      // Create a message hash and sign it
      const signature = await createAuthorizationSignature(
        agent,
        owner.address,
        incrementFunctionHash,
        currentTime,
        currentTime + 3600,
        2
      );

      await counter.authorizeAgent(
        agent.address,
        incrementFunctionHash,
        currentTime,
        currentTime + 3600,
        2, // Only 2 uses allowed
        signature
      );

      await counter.connect(agent).incrementMyCounter();
      expect(await counter.getCounter(owner.address)).to.equal(1);

      await counter.connect(agent).incrementMyCounter();
      expect(await counter.getCounter(owner.address)).to.equal(2);

      const authData = await counter.principalToAgentAuthorizations(owner.address, agent.address, incrementFunctionHash);
      expect(authData.allowedCalls).to.equal(0);
    });

    it("should respect time window for agent authorization", async function() {
      const { counter, owner, agent } = await loadFixture(deployFixture);
      const incrementFunctionHash = hre.ethers.id("incrementMyCounter()").slice(0, 10);
      const currentTime = await time.latest();

      // Create a message hash and sign it
      const signature = await createAuthorizationSignature(
        agent,
        owner.address,
        incrementFunctionHash,
        currentTime,
        currentTime + 3600,
        5
      );

      await counter.authorizeAgent(
        agent.address,
        incrementFunctionHash,
        currentTime,
        currentTime + 3600, // 1 hour window
        5,
        signature
      );

      await counter.connect(agent).incrementMyCounter();
      expect(await counter.getCounter(owner.address)).to.equal(1);

      await time.increase(3601);

      await expect(counter.connect(agent).incrementMyCounter()).to.be.revertedWith(
        "Agent not authorized: after end time"
      );
    });

    it("should not allow agent to act before start time", async function() {
      const { counter, owner, agent } = await loadFixture(deployFixture);
      const incrementFunctionHash = hre.ethers.id("incrementMyCounter()").slice(0, 10);
      const currentTime = await time.latest();

      // Create a message hash and sign it
      const signature = await createAuthorizationSignature(
        agent,
        owner.address,
        incrementFunctionHash,
        currentTime + 3600,
        currentTime + 7200,
        5
      );

      await counter.authorizeAgent(
        agent.address,
        incrementFunctionHash,
        currentTime + 3600, // Starts in 1 hour
        currentTime + 7200, // Ends in 2 hours
        5,
        signature
      );

      await expect(counter.connect(agent).incrementMyCounter()).to.be.revertedWith(
        "Agent not authorized: before start time"
      );
    });

    it("should allow authorization with no end time", async function() {
      const { counter, owner, agent } = await loadFixture(deployFixture);
      const incrementFunctionHash = hre.ethers.id("incrementMyCounter()").slice(0, 10);
      const currentTime = await time.latest();

      // Create a message hash and sign it
      const signature = await createAuthorizationSignature(
        agent,
        owner.address,
        incrementFunctionHash,
        currentTime,
        0,
        5
      );

      await counter.authorizeAgent(
        agent.address,
        incrementFunctionHash,
        currentTime,
        0, // No end time
        5,
        signature
      );

      await counter.connect(agent).incrementMyCounter();
      expect(await counter.getCounter(owner.address)).to.equal(1);

      await time.increase(100000);

      await counter.connect(agent).incrementMyCounter();
      expect(await counter.getCounter(owner.address)).to.equal(2);
    });
  });

  describe("Events", function() {
    it("should emit CounterIncremented event", async function() {
      const { counter, owner } = await loadFixture(deployFixture);
      await expect(counter.incrementMyCounter())
        .to.emit(counter, "CounterIncremented")
        .withArgs(owner.address, 1);
    });

    it("should emit CounterReset event", async function() {
      const { counter, owner } = await loadFixture(deployFixture);
      await counter.incrementMyCounter();
      await expect(counter.resetMyCounter())
        .to.emit(counter, "CounterReset")
        .withArgs(owner.address);
    });
  });

  describe("Protocol Functionality", function() {
    it("should allow the owner to authorize a new agent", async function() {
      const { counter, owner, anotherAgent } = await loadFixture(deployFixture);
      const incrementFunctionHash = hre.ethers.id("incrementMyCounter()").slice(0, 10);
      const currentTime = await time.latest();

      // Create a message hash and sign it
      const signature = await createAuthorizationSignature(
        anotherAgent,
        owner.address,
        incrementFunctionHash,
        currentTime,
        currentTime + 3600,
        5
      );

      await counter.authorizeAgent(
        anotherAgent.address,
        incrementFunctionHash,
        currentTime,
        currentTime + 3600,
        5,
        signature
      );

      const authData = await counter.principalToAgentAuthorizations(owner.address, anotherAgent.address, incrementFunctionHash);
      expect(authData.allowedCalls).to.equal(5);
    });

    it("should not allow unauthorized agent to increment the counter", async function() {
      const { counter, owner, unauthorizedAgent } = await loadFixture(deployFixture);

      expect(await counter.getCounter(unauthorizedAgent.address)).to.equal(0);
      await counter.connect(unauthorizedAgent).incrementMyCounter();
      expect(await counter.getCounter(unauthorizedAgent.address)).to.equal(1);

      expect(await counter.getCounter(owner.address)).to.equal(0);
    });

    it("should allow the owner to revoke an agent's authorization", async function() {
      const { counter, owner, agent } = await loadFixture(deployFixture);
      const incrementFunctionHash = hre.ethers.id("incrementMyCounter()").slice(0, 10);

      const currentTime = await time.latest();

      // Create a message hash and sign it
      const signature = await createAuthorizationSignature(
        agent,
        owner.address,
        incrementFunctionHash,
        currentTime,
        currentTime + 3600,
        5
      );

      await counter.authorizeAgent(
        agent.address,
        incrementFunctionHash,
        currentTime,
        currentTime + 3600,
        5,
        signature
      );

      await counter.connect(agent).incrementMyCounter();
      expect(await counter.getCounter(owner.address)).to.equal(1);

      const authData = await counter.principalToAgentAuthorizations(owner.address, agent.address, incrementFunctionHash);
      expect(authData.allowedCalls).to.equal(4);

      await counter.connect(owner).revokeAuthorization(agent.address, incrementFunctionHash);

      expect(await counter.agentToPrincipal(agent.address)).to.equal(hre.ethers.ZeroAddress);

      const updatedAuthData = await counter.principalToAgentAuthorizations(owner.address, agent.address, incrementFunctionHash);
      expect(updatedAuthData.allowedCalls).to.equal(0);
    });

    it("should allow the owner to update an agent's authorization", async function() {
      const { counter, owner, agent } = await loadFixture(deployFixture);
      const incrementFunctionHash = hre.ethers.id("incrementMyCounter()").slice(0, 10);
      const currentTime = await time.latest();

      await counter.updateAuthorization(
        agent.address,
        incrementFunctionHash,
        currentTime,
        currentTime + 7200,
        20
      );

      const authData = await counter.principalToAgentAuthorizations(owner.address, agent.address, incrementFunctionHash);
      expect(authData.allowedCalls).to.equal(20);
      expect(authData.endTime).to.equal(currentTime + 7200);
    });

    it("should not allow an agent to authorize another agent", async function() {
      const { counter, owner, agent, anotherAgent } = await loadFixture(deployFixture);
      const incrementFunctionHash = hre.ethers.id("incrementMyCounter()").slice(0, 10);
      const currentTime = await time.latest();

      // Create a message hash and sign it
      const signature = await createAuthorizationSignature(
        agent,
        owner.address,
        incrementFunctionHash,
        currentTime,
        currentTime + 3600,
        5
      );

      await counter.authorizeAgent(
        agent.address,
        incrementFunctionHash,
        currentTime,
        currentTime + 3600,
        5,
        signature
      );

      // Create a message for the agent to authorize another agent
      const signature2 = await createAuthorizationSignature(
        anotherAgent,
        agent.address,
        incrementFunctionHash,
        currentTime,
        currentTime + 3600,
        5
      );

      await expect(
        counter.connect(agent).authorizeAgent(
          anotherAgent.address,
          incrementFunctionHash,
          currentTime,
          currentTime + 3600,
          5,
          signature2
        )
      ).to.be.revertedWith("Caller is already an agent for another principal");
    });

    it("should emit AgentAuthorized event when authorizing an agent", async function() {
      const { counter, owner, anotherAgent } = await loadFixture(deployFixture);
      const incrementFunctionHash = hre.ethers.id("incrementMyCounter()").slice(0, 10);
      const currentTime = await time.latest();

      // Create a message hash and sign it
      const signature = await createAuthorizationSignature(
        anotherAgent,
        owner.address,
        incrementFunctionHash,
        currentTime,
        currentTime + 3600,
        5
      );

      await expect(
        counter.authorizeAgent(
          anotherAgent.address,
          incrementFunctionHash,
          currentTime,
          currentTime + 3600,
          5,
          signature
        )
      )
        .to.emit(counter, "AgentAuthorized")
        .withArgs(owner.address, anotherAgent.address, incrementFunctionHash);
    });

    it("should emit AgentRevoked event when revoking an agent", async function() {
      const { counter, owner, agent } = await loadFixture(deployFixture);
      const incrementFunctionHash = hre.ethers.id("incrementMyCounter()").slice(0, 10);

      await expect(counter.revokeAuthorization(agent.address, incrementFunctionHash))
        .to.emit(counter, "AgentRevoked")
        .withArgs(owner.address, agent.address, incrementFunctionHash);
    });

    it("should emit AgentAuthorizationUpdated event when updating an agent's authorization", async function() {
      const { counter, owner, agent } = await loadFixture(deployFixture);
      const incrementFunctionHash = hre.ethers.id("incrementMyCounter()").slice(0, 10);
      const currentTime = await time.latest();

      await expect(
        counter.updateAuthorization(
          agent.address,
          incrementFunctionHash,
          currentTime,
          currentTime + 7200,
          20
        )
      )
        .to.emit(counter, "AgentAuthorizationUpdated")
        .withArgs(owner.address, agent.address, incrementFunctionHash, currentTime, currentTime + 7200, 20);
    });

    it("should handle multiple function authorizations for same agent", async function() {
      const { counter, owner, agent } = await loadFixture(deployFixture);
      const incrementFunctionHash = hre.ethers.id("incrementMyCounter()").slice(0, 10);
      const dummyFunctionHash = hre.ethers.id("dummyFunction()").slice(0, 10);
      const currentTime = await time.latest();

      // Create a message hash and sign it
      const signature1 = await createAuthorizationSignature(
        agent,
        owner.address,
        incrementFunctionHash,
        currentTime,
        currentTime + 3600,
        5
      );

      await counter.authorizeAgent(
        agent.address,
        incrementFunctionHash,
        currentTime,
        currentTime + 3600,
        5,
        signature1
      );

      // Create a message hash and sign it
      const signature2 = await createAuthorizationSignature(
        agent,
        owner.address,
        dummyFunctionHash,
        currentTime,
        currentTime + 3600,
        3
      );

      await counter.authorizeAgent(
        agent.address,
        dummyFunctionHash,
        currentTime,
        currentTime + 3600,
        3,
        signature2
      );

      const auth1 = await counter.principalToAgentAuthorizations(owner.address, agent.address, incrementFunctionHash);
      const auth2 = await counter.principalToAgentAuthorizations(owner.address, agent.address, dummyFunctionHash);

      expect(auth1.allowedCalls).to.equal(5);
      expect(auth2.allowedCalls).to.equal(3);
    });

    it("should handle batch authorization correctly", async function() {
      const { counter, owner, agent, unauthorizedAgent } = await loadFixture(deployFixture);
      const incrementFunctionHash = hre.ethers.id("incrementMyCounter()").slice(0, 10);
      const currentTime = await time.latest();

      // Create message hashes and sign them
      const signature1 = await createAuthorizationSignature(
        agent,
        owner.address,
        incrementFunctionHash,
        currentTime,
        currentTime + 3600,
        5
      );

      const signature2 = await createAuthorizationSignature(
        unauthorizedAgent,
        owner.address,
        incrementFunctionHash,
        currentTime,
        currentTime + 3600,
        3
      );

      const batchData = [
        {
          agent: agent.address,
          functionSelector: incrementFunctionHash,
          startTime: currentTime,
          endTime: currentTime + 3600,
          allowedCalls: 5,
          signature: signature1
        },
        {
          agent: unauthorizedAgent.address,
          functionSelector: incrementFunctionHash,
          startTime: currentTime,
          endTime: currentTime + 3600,
          allowedCalls: 3,
          signature: signature2
        }
      ];

      await counter.batchAuthorizeAgent(batchData);

      const auth1 = await counter.principalToAgentAuthorizations(owner.address, agent.address, incrementFunctionHash);
      const auth2 = await counter.principalToAgentAuthorizations(owner.address, unauthorizedAgent.address, incrementFunctionHash);

      expect(auth1.allowedCalls).to.equal(5);
      expect(auth2.allowedCalls).to.equal(3);
    });

    it("should handle batch updates correctly", async function() {
      const { counter, owner, agent } = await loadFixture(deployFixture);
      const incrementFunctionHash = hre.ethers.id("incrementMyCounter()").slice(0, 10);
      const currentTime = await time.latest();

      // Create a message hash and sign it
      const signature = await createAuthorizationSignature(
        agent,
        owner.address,
        incrementFunctionHash,
        currentTime,
        currentTime + 3600,
        5
      );

      await counter.authorizeAgent(
        agent.address,
        incrementFunctionHash,
        currentTime,
        currentTime + 3600,
        5,
        signature
      );

      const updateSignature = await createAuthorizationSignature(
        agent,
        owner.address,
        incrementFunctionHash,
        currentTime,
        currentTime + 7200,
        7
      );

      const batchData = [{
        agent: agent.address,
        functionSelector: incrementFunctionHash,
        startTime: currentTime,
        endTime: currentTime + 7200, // Extended time
        allowedCalls: 7, // Increased calls
        signature: updateSignature
      }];

      await counter.batchAuthorizeAgent(batchData);

      const auth = await counter.principalToAgentAuthorizations(owner.address, agent.address, incrementFunctionHash);
      expect(auth.allowedCalls).to.equal(7);
      expect(auth.endTime).to.equal(currentTime + 7200);
    });

    it("should properly remove authorization when usage is depleted", async function() {
      const { counter, owner, agent } = await loadFixture(deployFixture);
      const incrementFunctionHash = hre.ethers.id("incrementMyCounter()").slice(0, 10);
      const currentTime = await time.latest();

      // Create a message hash and sign it
      const signature = await createAuthorizationSignature(
        agent,
        owner.address,
        incrementFunctionHash,
        currentTime,
        currentTime + 3600,
        1
      );

      await counter.authorizeAgent(
        agent.address,
        incrementFunctionHash,
        currentTime,
        currentTime + 3600,
        1, // Only one use
        signature
      );

      await counter.connect(agent).incrementMyCounter();

      const auth = await counter.principalToAgentAuthorizations(owner.address, agent.address, incrementFunctionHash);
      expect(auth.allowedCalls).to.equal(0);

      expect(await counter.agentToPrincipal(agent.address)).to.equal(hre.ethers.ZeroAddress);
    });

    it("should handle multiple agents for the same principal", async function() {
      const { counter, owner, agent, unauthorizedAgent } = await loadFixture(deployFixture);
      const incrementFunctionHash = hre.ethers.id("incrementMyCounter()").slice(0, 10);
      const currentTime = await time.latest();

      // Create message hashes and sign them
      const signature1 = await createAuthorizationSignature(
        agent,
        owner.address,
        incrementFunctionHash,
        currentTime,
        currentTime + 3600,
        2
      );

      const signature2 = await createAuthorizationSignature(
        unauthorizedAgent,
        owner.address,
        incrementFunctionHash,
        currentTime,
        currentTime + 3600,
        2
      );

      await counter.authorizeAgent(
        agent.address,
        incrementFunctionHash,
        currentTime,
        currentTime + 3600,
        2,
        signature1
      );

      await counter.authorizeAgent(
        unauthorizedAgent.address,
        incrementFunctionHash,
        currentTime,
        currentTime + 3600,
        2,
        signature2
      );

      await counter.connect(agent).incrementMyCounter();
      await counter.connect(unauthorizedAgent).incrementMyCounter();

      expect(await counter.getCounter(owner.address)).to.equal(2);
    });

    it("should properly handle authorization revocation", async function() {
      const { counter, owner, agent } = await loadFixture(deployFixture);
      const incrementFunctionHash = hre.ethers.id("incrementMyCounter()").slice(0, 10);
      const currentTime = await time.latest();

      // Create a message hash and sign it
      const signature = await createAuthorizationSignature(
        agent,
        owner.address,
        incrementFunctionHash,
        currentTime,
        currentTime + 3600,
        5
      );

      await counter.authorizeAgent(
        agent.address,
        incrementFunctionHash,
        currentTime,
        currentTime + 3600,
        5,
        signature
      );

      await counter.revokeAuthorization(agent.address, incrementFunctionHash);

      const auth = await counter.principalToAgentAuthorizations(owner.address, agent.address, incrementFunctionHash);
      expect(auth.allowedCalls).to.equal(0);

      expect(await counter.agentToPrincipal(agent.address)).to.equal(hre.ethers.ZeroAddress);

    });

    it("should prevent unauthorized revocation", async function() {
      const { counter, agent, unauthorizedAgent } = await loadFixture(deployFixture);
      const incrementFunctionHash = hre.ethers.id("incrementMyCounter()").slice(0, 10);

      await expect(counter.connect(unauthorizedAgent).revokeAuthorization(agent.address, incrementFunctionHash))
        .to.be.revertedWith("Unauthorized: caller is not the agent's principal");
    });
  });
});

