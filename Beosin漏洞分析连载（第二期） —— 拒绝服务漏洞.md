### 拒绝服务攻击(DOS)

对智能合约进行DOS攻击的方法有很多种，其基本的目的是使合约在一段时间或者永久无法正常运行。通过拒绝服务攻击，可以使合约中的ether永远无法提取出来。

下面将会列出几种常见的攻击场景：

#### 1.1 通过(Unexpected) Revert发动DoS

如果智能合约的状态改变依赖于外部函数执行的结果，又未对执行一直失败的情况做出防护，那么该智能合约就可能遭受DOS攻击。

- 案例

```{.solidity}
pragma solidity ^0.4.22;

contract Auction {
    address public currentLeader;
    uint256 public highestBid;
    
    function bid() public payable {
        require(msg.value > highestBid);
        require(currentLeader.send(highestBid));
        currentLeader = msg.sender;
        highestBid = currentLeader;
    }
}
```

案列合约是一个简单的竞拍合约，如果当前交易的携带的ether大于目前`highestBid`，那么`highestBid`所对应的ether就退回给`currentLeader`，然后设置当前竞拍者为`currentLeader`，`currentLeader`改为msg.value。但是当恶意攻击者部署如下合约，通过合约来竞拍将会出现问题：

```{.solidity}
pragma solidity ^0.4.22;

//设置原合约接口，方便调用函数
interface Auction{
    function bid() external payable;
}

contract POC {
    address owner;
    Auction auInstance;
    
    constructor() public {
        owner = msg.sender;
    }
    
    modifier onlyOwner() {
        require(owner==msg.sender);
        _;
    }
    //指向原合约地址
    function setInstance(address addr) public onlyOwner {
        auInstance = Auction(addr);
    }
    
    function attack() public onlyOwner {
        auInstance.bid.value(msg.value)();
    }   
    
    function() external payable{
        revert();
    }
}
```

攻击者先通过攻击合约向案例合约转账成为currentLeader，然后新的bider竞标的时候，执行到`require(currentLeader.send(highestBid))`会因为攻击合约的fallback()函数无法接收ether而一直为false，最后攻击合约以较低的ether赢得竞标。

- 漏洞修复

如果需要对外部函数调用的结果进行处理才能进入新的状态，请考虑外部调用可能一直失败的情况，也可以添加基于时间的操作，防止外部函数调用一直无法满足require判断。

#### 1.2 通过区块Gas Limit发动DoS

一次性向所有人转账，很可能会导致达到以太坊区块gas limit的上限。以太坊规定了每一个区块所能花费的gas
limit，如果超过交易便会失败。

即使没有故意的攻击，这也可能导致问题。然而，最为糟糕的是如果gas的花费被攻击者操控。在先前的例子中，如果攻击者增加一部分收款名单，并设置每一个收款地址都接收少量的退款。这样一来，更多的gas将会被花费从而导致达到区块gas limit的上限，整个转账的操作也会以失败告终。

- 案例

```{.solidity}
contract DistributeTokens {
    address public owner; // gets set somewhere
    address[] investors; // array of investors
    uint[] investorTokens; // the amount of tokens each investor gets
    
    // ... extra functionality, including transfertoken()
    
    function invest() public payable {
        investors.push(msg.sender);
        investorTokens.push(msg.value * 5); // 5 times the wei sent
        }
    
    function distribute() public {
        require(msg.sender == owner); // only owner
        for(uint i = 0; i < investors.length; i++) { 
            // here transferToken(to,amount) transfers "amount" of tokens to the address "to"
            transferToken(investors[i],investorTokens[i]); 
        }
    }
}
```

案例合约遍历可被人为操纵的investors\[\]数组。攻击者可以创建许多账户，使的investors\[\]数组变的很大，使得执行for循环所消耗的gas超过块gas极限，使得distribute函数一直处于out-of-gas（OOG）状态，而一直无法执行成功，合约正常功能实现受到影响。

- 漏洞修复

合约不应该循环对可以被外部用户人为操纵的数据结构进行批量操作，建议使用[取回模式而不是发送模式](https://solidity-cn.readthedocs.io/zh/develop/common-patterns.html#withdrawal-pattern)，每个投资者可以使用withdrawFunds取回自己应得的代币；

如果实在必须通过遍历一个变长数组来进行转账，最好估计完成它们大概需要多少个区块以及多少笔交易。然后你还必须能够追踪得到当前进行到哪以便当操作失败时从那里开始恢复，举个例子：

```
struct Payee {
    address addr;
    uint256 value;
}
Payee payees[];
uint256 nextPayeeIndex;

function payOut() {
    uint256 i = nextPayeeIndex;
    while (i < payees.length && msg.gas > 200000) {
      payees[i].addr.send(payees[i].value);
      i++;
    }
    nextPayeeIndex = i;
}
```

如上所示，必须确保在下一次执行`payOut()`之前另一些正在执行的交易不会发生任何错误。如果必须批量转账，请使用上面这种方式来处理。

#### 1.3 所有者操作

目前，很多代币合约都有一个ower账户，其拥有开启/暂停交易的权限，如果对owner保管不善，代币合约可能被一直冻结交易，导致非主观的拒绝服务攻击。

- 案例

```
bool public isFinalized = false;
address public owner; // gets set somewhere

function finalize() public {
    require(msg.sender == owner);
    isFinalized == true;
}

// ... extra ICO functionality

// overloaded transfer function
function transfer(address _to, uint _value) returns (bool) {
    require(isFinalized);
    super.transfer(_to,_value)
}
```

在ICO结束后，如果特权用户丢失其私钥或变为非活动状态，owner无法调用finalize()，用户则一直不可以发送代币，即令牌生态系统的整个操作取决于一个地址。

- 漏洞修复

可以设置多个拥有owner权限的地址，或者设置暂停交易的期限，超过期限就可以恢复交易，如：`require(msg.sender == owner || now > unlockTime)`

- 参考资料
  - https://blog.sigmaprime.io/solidity-security.html\#dos
  - 以太坊智能合约 --- 最佳安全开发指南 [通过(Unexpected)Throw发动DoS](https://github.com/ConsenSys/smart-contract-best-practices/blob/master/README-zh.md#%E9%80%9A%E8%BF%87unexpected-throw%E5%8F%91%E5%8A%A8dos)
  - 以太坊智能合约 --- 最佳安全开发指南 [通过区块GasLimit发动DoS](https://github.com/ConsenSys/smart-contract-best-practices/blob/master/README-zh.md#%E9%80%9A%E8%BF%87%E5%8C%BA%E5%9D%97gas-limit%E5%8F%91%E5%8A%A8dos)