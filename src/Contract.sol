pragma solidity >=0.7.0 <0.9.0;
pragma experimental ABIEncoderV2;

contract Tester {

    struct SearchIndex{
        uint id;
        string ipfsHash;
        string organization;
        string location;
        string month;
        string year;
        string token;
    }

    mapping (uint => SearchIndex) public index;
    event savingsEvent(uint indexed _indexId);
    uint public indexCount;

    constructor(){
        indexCount = 0;
    }

    function addIndex(string memory _ipfsHash, string memory _organization, string memory _location,
                        string memory _month, string memory _year, string memory _token) public {
        index[indexCount] = SearchIndex(indexCount, _ipfsHash, _organization, _location, _month, _year, _token);
        indexCount++;
    }

    function getMember() public view returns (string[] memory, string[] memory, string[] memory, string[] memory, string[] memory){
      string[]  memory org = new string[](indexCount);
      string[]  memory loc = new string[](indexCount);
      string[]  memory mon = new string[](indexCount);
      string[]  memory yr = new string[](indexCount);
      string[]  memory tok = new string[](indexCount);
      for (uint i = 0; i < indexCount; i++) {
          SearchIndex storage searchInd = index[i];
          org[i] = searchInd.organization;
          loc[i] = searchInd.location;
          mon[i] = searchInd.month;
          yr[i] = searchInd.year;
          tok[i] = searchInd.token;
      }
      return (org, loc, mon, yr, tok);
    }

    function getFile(uint _position) public view returns (string memory){
        SearchIndex storage searchInd = index[_position];
        return searchInd.ipfsHash;
    }

}