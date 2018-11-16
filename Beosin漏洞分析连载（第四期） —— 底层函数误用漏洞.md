### 1. 底层函数误用

`CALL` 与[`DELEGATECALL`](https://solidity.readthedocs.io/en/v0.4.24/units-and-global-variables.html#address-related)操作码是非常有用的，它们让 Ethereum开发者将他们的代码模块化（Modularise）。用 `CALL`操作码来处理对合约的外部标准信息调用（Standard MessageCall）时，代码在外部合约/功能的环境中运行。 `DELEGATECALL`操作码也是标准消息调用，但在目标地址中的代码会在调用合约的环境下运行，也就是说，保持`msg.sender` 和 `msg.value`不变。该功能支持实现库，开发人员可以为未来的合约创建可重用的代码。

#### 1.1 call注入攻击

`call`是以太坊智能合约编写语言Solidity提供的底层函数，用来与外部合约或者库进行交互。此类函数使用时需要对调用参数的安全性进行判定，建议谨慎使用。

- 案例

```{.solidity}
function transferFrom(address _from, address _to, uint256 _amount, bytes _data, string _custom_fallback)
        public
        returns (bool success)
    {
        // Alerts the token controller of the transfer
        if (isContract(controller)) {
            if (!TokenController(controller).onTransfer(_from, _to, _amount))
               throw;
        }

        require(super.transferFrom(_from, _to, _amount));

        if (isContract(_to)) {
            ERC223ReceivingContract receiver = ERC223ReceivingContract(_to);
            receiver.call.value(0)(bytes4(keccak256(_custom_fallback)), _from, _amount, _data);
        }

        ERC223Transfer(_from, _to, _amount, _data);

        return true;
    }
    
    function isAuthorized(address src, bytes4 sig) internal view returns (bool) {
    if (src == address(this)) {
        return true;
    } else if (src == owner) {
        return true;
    }
    ...
}
```

receiver，\_custom\_fallback，\_from, \_amount,
\_data是由用户控制的，也就是说用户可以控制整个call调用，包括调用的合约地址（receiver），调用哪个函数（\_custom\_fallback）,传递的参数（\_from,
\_amount,
\_data），是很危险的做法。攻击者通过指定receiver为案例合约地址，利用DS-Auth授权，调用合约自身的函数，从而获得了合约的控制权。

下面是ERC223标准的另一个call错误实现：

```{.solidity}
// Function that is called when a user or another contract wants to transfer funds .
function transfer(address _to, uint _value, bytes _data, string _custom_fallback) returns (bool success) {
    
  if(isContract(_to)) {
      if (balanceOf(msg.sender) < _value) throw;
      balances[msg.sender] = safeSub(balanceOf(msg.sender), _value);
      balances[_to] = safeAdd(balanceOf(_to), _value);
      assert(_to.call.value(0)(bytes4(sha3(_custom_fallback)), msg.sender, _value, _data));
      Transfer(msg.sender, _to, _value, _data);
      return true;
  }
  else {
      return transferToAddress(_to, _value, _data);
  }
}
```

这种合约本身允许用户自定义 `call()` 任意地址上任意函数的设计，十分危险。攻击者可以很容易地借用当前合约的身份来进行**任何操作**。
可能导致如下后果：

1. 允许攻击者以缺陷合约身份来盗走其它 Token 合约中的 Token
2. 与 ds-auth 之类的鉴权机制结合，绕过合约自身的权限检查
3. 允许攻击者以缺陷合约身份来盗走其它 Token 账户所授权（Approve）的
   Token
4. 攻击者可传入虚假数据（\_data）欺骗 Receiver 合约

- 漏洞修复

1. 推荐使用如下方式调用tokenFallback函数

```{.solidity}
interface ERC223ReceivingContract {
    function tokenFallback(address from,uint256 );
}
   function transfer(address _to, uint _value, bytes _data) {
        ...
        if(codeLength>0) {
            ERC223ReceivingContract receiver = ERC223ReceivingContract(_to);
            receiver.tokenFallback(msg.sender, _value, _data);//限定调用函数
        }
        ...
    }
```

1. DS-Auth在设置权限的时候，不要把合约本身地址加入白名单

```{.solidity}
function isAuthorized(address src, bytes4 sig) internal view returns (bool) {
    if (src == address(this)) {
        return false;
    } else if (src == owner) {
        return true;
    }
    ...
}
```

- 参考资料
  - [ATN抵御合约攻击的报告](https://atn.io/resource/aareport.pdf)
  - [以太坊智能合约call注入攻击](https://blog.csdn.net/u011721501/article/details/80757811)
  - [ds-auth](https://github.com/dapphub/ds-auth)
  - [ERC223-token-standard](https://github.com/Dexaran/ERC223-token-standard/tree/Recommended)

#### 1.2 delegatecall误用

`DELEGATECALL`
会保持调用环境不变的属性表明，构建无漏洞的定制库并不像人们想象的那么容易。库中的代码本身可以是安全的，无漏洞的，但是当在另一个应用的环境中运行时，可能会出现新的漏洞。

- 案例

案例代码来源于[Ethernaut第6关](https://ethernaut.zeppelin.solutions/level/0x68756ad5e1039e4f3b895cfaa16a3a79a5a73c59)

```{.solidity}
pragma solidity ^0.4.18;

contract Delegate {

  address public owner;

  function Delegate(address _owner) public {
    owner = _owner;
  }

  function pwn() public {
    owner = msg.sender;
  }
}

contract Delegation {

  address public owner;
  Delegate delegate;

  function Delegation(address _delegateAddress) public {
    delegate = Delegate(_delegateAddress);
    owner = msg.sender;
  }

  function() public {
    if(delegate.delegatecall(msg.data)) {
      this;
    }
  }
}
```

在主合约Delegation的fallback函数中，可通过delegatecall调用Delegate合约的函数，并在主合约环境下执行，如果msg.data是`0xdd365b8b`(pwn()的函数签名)，即调用Delegate的pwn函数，那么消息发起者就可以变成主合约的owner。

- 漏洞修复

Solidity 为实现库合约提供了关键字 `library` （参考 [SolidityDocs](http://solidity.readthedocs.io/en/latest/contracts.html#libraries) 了解更多详情)。这确保了`library` 是无状态（Stateless）且不可自毁的。强制让`library` 成为无状态的，可以缓解本节所述的存储环境的复杂性。无状态`library` 还可以防止攻击者直接修改`library` 状态以实现对依赖于`library` 代码的合约的攻击。在使用时 `DELEGATECALL` 时要特别注意库合约和调用合约可能对状态变量进行修改，并且尽可能构建无状态`library` 。

- 参考链接：

  [Ethernaut](https://ethernaut.zeppelin.solutions)

  https://blog.sigmaprime.io/solidity-security.html#delegatecall