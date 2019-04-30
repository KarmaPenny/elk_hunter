package main

import (
	. "github.com/KarmaPenny/golib/dynamics"
	"github.com/KarmaPenny/golib/elk"
	"github.com/KarmaPenny/golib/service"

	"encoding/json"
	"fmt"
	"crypto/tls"
	"log"
	"net/http"
	"runtime"
	"time"
)

var client elk.Client = elk.Client{
	BaseUrl: "https://elk:FSCiWb9vsxoU8GPh@localhost:9200",
	HttpClient: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}},
}

// use logs refresh interval to prevent scanning time range when logs are not searchable yet
var logs_refresh_interval time.Duration

func main() {
	// set logs_refresh_interval
	var err error
	logs_refresh_interval, err = client.GetRefreshInterval("logs-*")
	for err != nil && !service.Stopping() {
		log.Printf("[ERROR] unable to get logs index refresh interval: %s", err)
		time.Sleep(time.Second)
		logs_refresh_interval, err = client.GetRefreshInterval("logs-*")
	}

	// create an elk job pipeline
	pipeline := elk.JobPipeline{
		Client: &client,
		TaskName: "elk_hunter",
		Index: "hunts",
		Filter: Object{"bool": Object{"filter": Array{Object{"range": Object{"next_run_time": Object{"lt": "now"}}}, Object{"term": Object{"enabled": true}}}}},
		Order: Array{Object{"next_run_time": "asc"}},
		Task: RunHunt,
		NumWorkers: runtime.NumCPU(),
	}

	// start the pipeline and stop it when exiting
	pipeline.Start()
	defer pipeline.Stop()

	// process the pipeline until the service stops
	for !service.Stopping() {
		pipeline.Process()
	}
}

func RunHunt(hunt *elk.Document) {
	log.Printf("[DEBUG] executing %s", hunt.Id)
	start_time := time.Now()

	// get hunt info
	query := Object{}
	err := json.Unmarshal([]byte(hunt.Source.GetString("query", "{}")), &query)
	if err != nil {
		log.Printf("[ERROR] unable to parse hunt query %s: %s", hunt.Id, err)
		return
	}
	run_interval := time.Duration(hunt.Source.GetInt("run_interval", 60000)) * time.Millisecond
	last_run_time := hunt.Source.GetString("last_run_time", "0")
	alerts := hunt.Source.GetBool("alerts", false)
	indicator_types := hunt.Source.GetArray("indicator_types", Array{})
	indicators := []string{}

	// determine run time
	run_time := elk.Timestamp(time.Now().Add(-2 * logs_refresh_interval))

	// create multi-search from template
	search := Array{}

	// build the search template
	search_template := Object{
		"size": 10000,
		"_source": false,
		"query": Object{
			"bool": Object{
				"filter": Array{
					Object{
						"range": Object{
							"@index_timestamp": Object{
								"gte": last_run_time,
								"lt": run_time,
							},
						},
					},
					query,
				},
			},
		},
	}

	// if hunt uses indicators
	if len(indicator_types) > 0 {
		// lookup indicators
		indicator_lookup := Object{
			"size": 100000,
			"_source": Array{"value"},
			"query": Object{
				"bool": Object{
					"filter": Array{
						Object{
							"terms": Object{
								"type": indicator_types,
							},
						},
						Object{
							"term": Object{
								"enabled": true,
							},
						},
					},
				},
			},
		}
		results, err := client.Search("indicators", indicator_lookup)
		if err != nil {
			log.Printf("[ERROR] failed to get indicators: %s", err)
			return
		}

		// search for each indicator
		for i := range results {
			if value := results[i].Source.GetString("value", ""); value != "" {
				indicators = append(indicators, results[i].Path())
				search = append(search, Object{})
				search = append(search, Object{"source": search_template, "params": Object{"indicator":value}})
			}
		}
	} else {
		// search without indicators
		search = append(search, Object{})
		search = append(search, Object{"source": search_template, "params": Object{}})
	}

	// check for empty search
	if len(search) == 0 {
		log.Printf("[ERROR] hunt %s has no searches", hunt.Id)
		return
	}

	// run the search
	results, err := client.MultiSearchTemplate("logs", search)
	if err != nil {
		log.Printf("[ERROR] failed to run hunt %s: %s", hunt.Id, err)
		return
	}

	// create analysis for each hit
	analysis_type := fmt.Sprintf("%s_hunt", hunt.Id)
	analysis_version := fmt.Sprintf("%d", hunt.Version)
	analyses := map[string]*elk.Analysis{}
	for i := range results {
		for j := range results[i] {
			path := results[i][j].Path()
			log.Printf("[INFO] %s hit %s", hunt.Id, path)
			if _, ok := analyses[path]; !ok {
				analyses[path] = elk.NewAnalysis(analysis_type, analysis_version, run_time)
			}
			analyses[path].AddObservable(hunt.Path())
			if i < len(indicators) {
				analyses[path].AddObservable(indicators[i])
			}
		}
	}

	// bulk update matched logs
	updates := elk.BulkUpdate{}
	for path := range analyses {
		if _, ok := updates[path]; !ok {
			updates[path] = elk.NewUpdate(path)
		}
		updates[path].CreateField("analysis_status", elk.ANALYSIS_STATUS_QUEUED)
		if alerts {
			updates[path].CreateField("alert_status", elk.ALERT_STATUS_QUEUED)
		}
		for i := range analyses[path].Observables {
			updates[path].AppendField("observables", analyses[path].Observables[i])
		}
		for i := range analyses[path].Tags {
			updates[path].AppendField("tags", analyses[path].Tags[i])
		}
		updates[path].SetAnalysis(analysis_type, analyses[path])
	}
	if _, err := client.Push(updates); err != nil {
		log.Printf("[ERROR] failed to update matched logs: %s", err)
		return
	}

	took := time.Since(start_time).Nanoseconds() / 1000000
	log.Printf("[DEBUG] %s took %dms", hunt.Id, took)

	// update the hunt for next run
	update := Object{
		"doc": Object{
			"took": took,
			"last_run_time": run_time,
			"next_run_time": elk.Timestamp(time.Now().Add(run_interval).Add(2 * logs_refresh_interval)),
		},
	}
	_, err = client.Update(hunt.Path(), &update)
	if err != nil {
		log.Printf("[ERROR] failed to update hunt %s: %s", hunt.Id, err)
		return
	}
}
