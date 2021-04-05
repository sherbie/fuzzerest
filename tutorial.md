# Tutorial

This doc is a crash course on using fuzzeREST.

## Mock server

Practice using fuzzeREST by using [test/mockserver.py](test/mockserver.py) as a target.

First, start the server for fuzzing:

```
$ make run-mockserver
```

## Models

fuzzeREST requires a fuzzing model to know where and how to fuzz a specific service's endpoint.

For example, the tutorial model file [tutorial.json](fuzzerest/models/tutorial.json) defines the required details to fuzz the `/watch` endpoint hosted at the `example` domain. This model instructs fuzzeREST to send requests to the service listening for `http` connections at the host `localhost` port `8080`. These requests will be targeted to the `/watch` endpoint using the `GET` method and an input query consisting of two parameters `v` and `t` with the initial values `9bZkp7q19f0` and `1m05s` respectively.

## Fuzz it!

Run the fuzzer client to send three (`-i=3`) requests using the [tutorial.json](fuzzerest/models/tutorial.json) model file (`--model-path fuzzerest/models/tutorial.json`) against the `default` domain (`--domain default`) with full debug log (`--loglevel 0`) for further analysis:

```
$ fuzzerest -i=3 --model-path fuzzerest/models/tutorial.json --loglevel 0
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
$ cat results/20210405134218-tutorial_all_uris_all_methods.log
(...)
2021-04-05 13:34:17,907 DEBUG: {'method': 'GET', 'headers': {'X-fuzzeREST-State': '0'}, 'body': None, 'delay': 0, 'url': 'http://localhost:8080/watch?v[]=9bZkp7q19f0&t[]=1m05s', 'size': 81, 'time': 0.004, 'error': None, 'response_text': '{"success": false, "reason": "Video not found"}\n', 'status_code': 200}
(...)
```

In the above output, the field `response` stores the data received by the service when sending a request which details are summarized by the `methods`, `headers`, `url`, `body` and `size` fields.

## Custom mutation

A mutation is a variation applied to the fuzzer's input data. fuzzeREST has a defined strategy to decide how to mutate input values. This can be controlled by you. Control is provided by what we call mutation placeholders which have the form `{name}` and are part of the fuzzing model.

Coming back to fuzzing the `example` domain, we can now make use of mutation placeholders to control what gets modified or mutated. Taking the original [tutorial.json](fuzzerest/models/tutorial.json) model we add the next modification to the `t` data field as follows:

```
      "input": {
        "query": {
          "v": "9bZkp7q19f0",
          "t": "1m{mutate_here}05s"
        }
      }
```

The above modification to the model will instruct fuzzeREST to mutate the `t` data field only where the mutation placeholder `{mutate_here}` is located, leaving the rest of that field untouched.

## Fuzz it, again!

Run the fuzzer again and see the differences with the new model:

```
$ fuzzerest -i=3 --model-path fuzzerest/models/tutorial.json --domain default --loglevel 1
```

In the results below you can verify how the `t` data field has been mutated differently this time by leaving the data chunks `1m` and `05s` intact:

```
$ cat results/20210405134244-tutorial_all_uris_all_methods.log
(...)
2021-04-05 13:42:52,962 WARNING: state=1 method=GET uri=/watch code=200 error="None"
2021-04-05 13:42:52,962 DEBUG: {'method': 'GET', 'headers': {'X-fuzzeREST-State': '1'}, 'body': None, 'delay': 0, 'url': 'http://localhost:8080/watch?v=340282366920938463463374607431768211457bZkp7q19f0&t=1m340282366920938463463374607431768211457m05s', 'size': 155, 'time': 0.003, 'error': None, 'response_text': '{"success": false, "reason": "Video not found"}\n', 'status_code': 200}
(...)
```

## Constants

For more granular control, fuzzeREST allows you to lock placeholders with an unchangeable value. These constants can be defined in either a file like [constants.json](test/constants.json) or via CLI arguments.

First, update the fuzzing model [tutorial.json](fuzzerest/models/tutorial.json) to include two new constants names as `{endpoint}` and `{time}`:

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

Next, define the value of the new constant `{endpoint}` in the [constants.json](test/constants.json) file as follows:

```
{
  "{endpoint}": "watch"
}
```

Then, use the command line parameters `--constants` and `--constants-file` to define the value of the `{time}` constant, and to include the [constants.json](test/constants.json) file respectively:

```
$ fuzzerest -i=3 --model-path fuzzerest/models/tutorial.json --domain default --loglevel 1 --constants '{"{time}": "1m05s"}' --constants-file test/constants.json
```

## Fuzz it, once more

Run the fuzzer with the new command line and see how the constants get replaced in the results:

```
$ fuzzerest -i=3 --model-path fuzzerest/models/tutorial.json --domain default --loglevel 1 --constants '{"{time}": "1m05s"}' --constants-file test/constants.json

$ cat results/20210405135517-tutorial_all_uris_all_methods.log
(...)
2021-04-05 13:55:17,886 DEBUG: http://localhost:8080 "GET /watch?v=340282366920938463463374607431768211457bZkp7q19f0&t=340282366920938463463374607431768211457m05s HTTP/1.1" 200 48
(...)
2021-04-05 13:55:17,897 DEBUG: http://localhost:8080 "GET /watch?v=9bZkp7q19fp7q19fp7qbZkp7q19bZkp7q19bZkp7q255f429bZkp7q197&t=1m05s HTTP/1.1" 200 48
```

## Behavior replication

fuzzeREST can reproduce identical output on demand. Doing so requires identical input. During execution, the fuzzer will
log each request the fuzzer made with an input summary. One important value to look at is the state value. This is the seed number of the fuzzer. It therefore follows that fuzzeREST will always produce the same output given that it reads the same model, input arguments and state number.

For portability, fuzzeREST can export a particular request configuration to [curl](https://curl.se/) format. Let's
consider the following command to demonstrate:

```
$ fuzzerest -s 3 --model-path fuzzerest/models/tutorial.json --domain default --constants '{"{time}": "1m05s"}' --constants-file test/constants.json --loglevel 0 --printcurl -u /watch --method GET
```

... generates the following output:

```
 ---> Printing curl:
curl -g -K results/curl-config.txt
```

The resulting config file will look something like so:

```
$ cat results/curl-config.txt
request = GET
header = "X-fuzzeREST-State: 3"
url = "http://localhost:8080/watch?v[]=9bZkp7q19f0&t[]=1m05s"
```
