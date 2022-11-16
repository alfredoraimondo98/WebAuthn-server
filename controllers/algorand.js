const algosdk = require('algosdk');
 

exports.createAccount = async (req, res, next) => {

    const server="https://testnet-algorand.api.purestake.io/ps2";
    const port="";
    const token={
        "x-api-key": "cFytdDh7ETMLwFujzahn1V7710kbJFL5ZPIZhOMj" // fill in yours
    };

    let client = new algosdk.Algodv2(token,server,port);

    
    let account = algosdk.generateAccount();
    console.log("Account Address: ", account.addr);
    
    let mn = algosdk.secretKeyToMnemonic(account.sk);
    console.log("Account Mnemonic: ", mn);

    console.log("Account ", account)

    console.log("account information ", client.accountInformation(account.addr))

  

    res.send(account)
    
}


exports.getBalance = (req, res, next) => {
    
    const server="https://testnet-algorand.api.purestake.io/ps2";
    const port="";
    const token={
        "x-api-key": "cFytdDh7ETMLwFujzahn1V7710kbJFL5ZPIZhOMj" // fill in yours
    };

    let client=new algosdk.Algodv2(token,server,port);

    let account1 = 'Z7ITFTDEHJTFTIFDYBVZBO5PWLWWTIUA2PFBVJFQ75VUVCJFMU3VPRONK4';
    // Account 1 Mnemonic:  gospel term season cement bench window owner pumpkin insect boat kind defy clump trust recycle include taxi tornado spin original tooth clutch spend absorb put
   // let mnemonico = "gospel term season cement bench window owner pumpkin insect boat kind defy clump trust recycle include taxi tornado spin original tooth clutch spend absorb put"
    //let account2 = '6NAKWTCPPHB4RZFYS26RT5QDCO6BFNVY3OYJV4WPMGOPDPFOB2GCSR5Z4M';

   // let privKey = algosdk.mnemonicToSecretKey(mnemonico)
   // console.log("priv key ", privKey)


    ( async() => {
        let account1_info = (await client.accountInformation(account1).do());
        console.log("Balance of account 1: " + JSON.stringify(account1_info.amount));
        
    })().catch(e => {
        console.log(e);
    })
}