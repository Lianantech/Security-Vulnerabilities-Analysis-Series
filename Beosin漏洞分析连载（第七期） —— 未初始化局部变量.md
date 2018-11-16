### 1. 使用未初始化的存储器局部变量

函数中的局部变量默认为存储或内存，具体取决于其类型。
未初始化的本地存储变量可以指向合约中的其他意外存储变量，从而导致故意（即开发人员故意将它们放在那里进行攻击）或无意的漏洞。

错误代码示例：

-   未初始化的结构体局部变量：
``` {.solidity}
pragma solidity ^0.4.22;

contract NameRegistrar {

    bool public unlocked = false;  // registrar locked, no name updates

    struct NameRecord { // map hashes to addresses
        bytes32 name;  
        address mappedAddress;
    }

    mapping(address => NameRecord) public registeredNameRecord; // records who registered names 
    mapping(bytes32 => address) public resolve; // resolves hashes to addresses

    function register(bytes32 _name, address _mappedAddress) public {
        // set up the new NameRecord
        NameRecord newRecord;
        newRecord.name = _name;
        newRecord.mappedAddress = _mappedAddress; 

        resolve[_name] = _mappedAddress;
        registeredNameRecord[msg.sender] = newRecord; 

        require(unlocked); // only allow registrations if contract is unlocked
    }
}
```

当输入\_name="0x0000000000000000000000000000000000000000000000000000000000000001"(63个0)，地址任意地址时，会覆盖unlocked的值，使其变为true。

- 未初始化的数组局部变量：

``` {.solidity}
pragma solidity ^0.4.24;
pragma experimental ABIEncoderV2;

contract UnfixedArr {
    
    bool public frozen = false;
    
    function wrongArr(bytes[] elements) public {
        bytes[1] storage arr;
        arr[0] = elements[0];
    }
}
```

当输入elements=\["0x0000000000000000000000000000000000000000000000000000000000000001"\](63个0)，会覆盖frozen的值，使其变为true。

* 漏洞修复

Remix-ide等编译器会对未初始化的存储器局部变量进行告警，开发人员不能忽略这个警告，在声明变量时，应对这些存储器局部变量进行初始化，避免安全漏洞。也可以使用memory关键词指定变量存储在memory中，避免覆盖存储在storage中的状态变量。