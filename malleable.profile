http-get "customc2" {

    # We just need our URI to be something unique and recognizable in order for GraphStrike to parse out values
    set uri "/_";
    set verb "GET";

    client {

        metadata {
            base64url;
            uri-append;
        }
    }

    server {

        output {   
            print;
        }
    }
}

http-post "customc2" {

    # We just need our URI to be something unique and recognizable in order for GraphStrike to parse out values
    set uri "/-_";
    set verb "POST";

    client {
       
        id {
            uri-append;         
        }
              
        output {
            print;
        }
    }

    server {

        output {
            print;
        }
    }
}