# Introduction to Metasploit
## Understanding the Architecture
By default, all the base files related to Metasploit Framework can be found under `/usr/share/metasploit-framework`.

**Data, Documentation, Lib**
- These are the base files for the Framework. The Data and Lib are the functioning parts of the msfconsole interface, while the Documentation folder contains all the technical details about the project.

**Modules**
- They are contained in the following folders: 
    ```
    $ ls /usr/share/metasploit-framework/modules

    auxiliary  encoders  evasion  exploits  nops  payloads  post
    ```

**Plugins**
- Plugins offer the pentester more flexibility when using the msfconsole since they can easily be manually or automatically loaded as needed to provide extra functionality and automation during our assessment.
    ```
    $ ls /usr/share/metasploit-framework/plugins/

    aggregator.rb      ips_filter.rb  openvas.rb           sounds.rb
    alias.rb           komand.rb      pcap_log.rb          sqlmap.rb
    auto_add_route.rb  lab.rb         request.rb           thread.rb
    beholder.rb        libnotify.rb   rssfeed.rb           token_adduser.rb
    db_credcollect.rb  msfd.rb        sample.rb            token_hunter.rb
    db_tracker.rb      msgrpc.rb      session_notifier.rb  wiki.rb
    event_tester.rb    nessus.rb      session_tagger.rb    wmap.rb
    ffautoregen.rb     nexpose.rb     socket_logger.rb
    ```

**Scripts**
- Meterpreter functionality and other useful scripts.
    ```
    $ ls /usr/share/metasploit-framework/scripts/

    meterpreter  ps  resource  shell
    ```

**Tools**
- Command-line utilities that can be called directly from the msfconsole menu.
    ```
    $ ls /usr/share/metasploit-framework/tools/

    context  docs     hardware  modules   payloads
    dev      exploit  memdump   password  recon
    ```

## Questions
1. Which version of Metasploit comes equipped with a GUI interface? **Answer: Metasploit Pro**
2. What command do you use to interact with the free version of Metasploit? **Answer: msfconsole**