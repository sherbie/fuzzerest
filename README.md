# fuzzeREST

"Fuzzing or fuzz testing is an automated software testing technique that involves providing invalid, unexpected, or random data as inputs to a computer program." [Fuzzing - OWASP](https://www.owasp.org/index.php/Fuzzing)

fuzzeREST is a hard fork of [Hot-Fuzz](https://github.com/Unity-Technologies/hot-fuzz).

## Setup

```
$ make setup
```

Once your setup is done. You'll need to install fuzzeREST locally. Using a virtual environment is recommended.

```
pip install -e .
```

## Fuzzing

Practice using fuzzeREST by using [test/mockserver.py](test/mockserver.py) as a target.

First, start the server fuzzing:

```
$ make run-mockserver
```

### Models

fuzzeREST requires a fuzzing model to know where and how to fuzz a specific service's endpoint.

For instance, the example model file [tutorial.json](fuzzerest/models/tutorial.json) defines the required details to fuzz the `/watch` endpoint hosted at the `example` domain as follows:

```
{
  "domains": {
    "example": {
      "host": "localhost",
      "port": 8080,
      "protocol": "http"
    }
  },
  "endpoints": [
    {
      "uri": "/watch",
      "comment": "watch video",
      "methods": ["GET"],
      "input": {
        "query": {
          "v": "9bZkp7q19f0",
          "t": "1m05s"
        }
      }
    }
  ]
}
```

This model instructs fuzzeREST to send requests to the service listening for `http` connections at the host `localhost` port `8080`. These requests will be targeted to the `/watch` endpoint using the `GET` method and an input query consisting of two parameters `v` and `t` with the initial values `9bZkp7q19f0` and `1m05s` respectively.

### Fuzz it!

Run the fuzzer client to send three (`-i=3`) requests using the `tutorial.json` model file (`--model-path fuzzerest/models/tutorial.json`) against the `example` domain (`--domain example`) with full debug log (`--loglevel 0`) for further analysis:

```
$ fuzzerest -i=3 --model-path fuzzerest/models/tutorial.json --domain example --loglevel 0
```

Running the fuzzer successfully will generate no feedback output and leave the results under the `results` directory. Here we can have a more detailed look of how fuzzeREST has sent the requests and how certain data fields were modified to fuzz the target endpoint.

In the output below you can see how the original values of the fields `v` and `t` have been modified. Sometimes these values remain the same, sometimes these have small variations and in other cases these have been completely replaced with "known-to-be-dangerous" values:

```
$ cat results/20170907164501_all_uris_all_methods.log
(...)
2017-09-07 16:45:01,476 DEBUG: http://localhost:8080 "GET /watch?v[]=9bZkp7q19f0&t=0m00m00s HTTP/1.1" 200 None
(...)
2017-09-07 16:45:01,522 DEBUG: http://localhost:8080 "GET /watch?v=340282366920938463463374607431768211457bZkp7q19f0&t=%3Cimg%20%5Cx12src%3Dx%20onerror%3D%22javascript%3Aalert%281%29%22%3E HTTP/1.1" 200 None
(...)
2017-09-07 16:45:01,538 DEBUG: http://localhost:8080 "GET /watch?v=9bZkp7q19fp7q19fp7qbZkp7q19bZkp7q19bZkp7q255f429bZkp7q197&t=1m05s HTTP/1.1" 200 None
```

fuzzeREST will also log information about the response received by the service and more details about the request sent:

```
$ cat results/20170907164501_all_uris_all_methods.log
(...)
2017-09-07 16:45:01,513 ERROR: {"method": "GET", "headers": {"X-fuzzeREST-State": "0"}, "url": "http://localhost:8080/watch?v[]=9bZkp7q19f0&t=0m00m00s", "body": null, "size": 359, "response": "{\"success\": false, \"reason\": \"Not found\"}\n", "reason": "OK", "httpcode": 200, "time": 0.049}
(...)
```

In the above output, the field `response` stores the data received by the service when sending a request which details are summarized by the `methods`, `headers`, `url`, `body` and `size` fields.

### Custom mutation

In Fuzzing, mutation is commonly understood as the variations applied to the input data required to fuzz a given program. fuzzeREST has a defined strategy to decide how to mutate input values, but it also offers to user a level of control over it. This control is provided by what we call the mutation placeholders which have the form `{name}` and are part of the fuzzing model.

Coming back to fuzzing the `example` domain, we can now make use of mutation placeholders to control what gets modified or mutated. Taking the original [tutorial.json](fuzzerest/models/tutorial.json) model we add the next modification to the `t` data field as follows:

```
      "input": {
        "query": {
          "v": "9bZkp7q19f0",
          "t": "1m{mutate_here}05s"
        }
      }
```

The above modification to the model will instruct fuzzeREST to only mutate the `t` data field where the mutation placeholder `{mutate_here}` is located and let the rest of the data field untouched.

### Fuzz it, again!

Run the fuzzer again and see the differences with the new model:

```
$ ./cli.py -i=3 --model-path fuzzerest/models/tutorial.json --domain example --loglevel 0
```

In the results below you can verify how the `t` data field has been mutated differently this time by leaving the data chunks `1m` and `05s` intact:

```
$ cat results/20170907182405_all_uris_all_methods.log
(...)
2017-09-07 18:24:05,402 DEBUG: http://localhost:8080 "GET /watch?v[]=9bZkp7q19f0&t=1m%20%20%20%C2%9F%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%C2%80a%C2%8Aa05s HTTP/1.1" 200 None
(...)
2017-09-07 18:24:05,430 DEBUG: http://localhost:8080 "GET /watch?v=340282366920938463463374607431768211457bZkp7q19f0&t=1mo%CC%82%C2%8F%C2%BF3%E2%81%844a05s HTTP/1.1" 200 None
```

### Constants

To add further customization, fuzzeREST allows to define data values in your model which may change or remain across different fuzzing runs, we call them constants. These can be detailed in either, a file like [constants.json](test/constants.json) or in the command line.

First, update the fuzzing model `tutorial.json` to include two new constants name as `{endpoint}` and `{time}`:

```
  "endpoints": [
    {
      "uri": "/{endpoint}",
      "comment": "watch video",
      "methods": ["GET"],
      "input": {
        "query": {
          "v": "9bZkp7q19f0",
          "t": "{time}"
        }
      }
    }
  ]
```

Next, define the value of the new constant `{endpoint}` in the `constants.json` file as follows:

```
{
  "{endpoint}": "watch"
}
```

Then, use the command line parameters `--constants` and `--constants-file` to define the value of the `{time}` constant, and to include the `constants.json` file respectively:

```
(...) --constants '{"{time}": "1m05s"}' --constants-file test/constants.json (...)
```

### Fuzz it, once more

Run the fuzzer with the new command line and see how the constants get replaced in the results:

```
$ ./cli.py -i=3 --model-path fuzzerest/models/tutorial.json --domain example --constants '{"{time}": "1m05s"}' --constants-file test/constants.json --loglevel 0

$ cat results/20171204173210_all_uris_all_methods.log
(...)
2017-12-04 17:32:10,403 DEBUG: http://localhost:8080 "GET /watch?v=340282366920938463463374607431768211457bZkp7q19f0&t=%3Cimg%20%5Cx12src%3Dx%20onerror%3D%22javascript%3Aalert%281%29%22%3E HTTP/1.1" 200 None
(...)
2017-12-04 17:32:10,425 DEBUG: http://localhost:8080 "GET /watch?v=9bZkp7q19fp7q19fp7qbZkp7q19bZkp7q19bZkp7q255f429bZkp7q197&t=1m05s HTTP/1.1" 200 None
```
