Server Instructions:
===============================================================================
StartUp
    - wbs379 portnumber {-f statefile | -n entries}
    - eg. wbs379 2222 -n 100
    - eg. wbs379 2222 -f whiteboard.all

Client Instructions:
===============================================================================
StartUp
    - wbc379 hostname portnumber [keyfile]
    - eg. wbc379 hostname 2222 key.txt

Upon connection to the server:
    - The user will have to choose one of three options
        - 1. (Submit: 1) Query an entry on the server: Look up the value of an entry in the server whiteboard
        - 2. (Submit: 2) Update an entry on the server: Submit a new whiteboard message for a given entry on the whiteboard
        - 3. (Submit: exit) Exit the client.
    
    - If the user choose to query the server whiteboard or update the server whiteboard then they will next be prompted to enter the
    number of the entry they wish to update.

    - (a) After if the user decided to query the server after they have submitted their query, it will be sent to the server and the 
    whiteboard message will be presented.

    - (b)
        - After if the user decided to update the server they will be asked to type out their message.
        - Thereafter they will be prompted if they want to upload the whiteboard message as a encrypted message (submit y or n for yes or no, respectively).