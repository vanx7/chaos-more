/*
 * Copyright 2021 Chaos Mesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

import { Box, Grid, Grow } from '@mui/material'
import { useEffect, useState } from 'react'

import { Event } from 'api/events.type'
import EventsTimeline from 'components/EventsTimeline'
import { ExperimentSingle } from 'api/experiments.type'
import Loading from '@ui/mui-extends/esm/Loading'
import Paper from '@ui/mui-extends/esm/Paper'
import PaperTop from '@ui/mui-extends/esm/PaperTop'
import T from 'components/T'
import api from 'api'
import { useParams } from 'react-router-dom'

export default function Observe() {
  const { uuid } = useParams()

  const [loading, setLoading] = useState(true)
  const [single, setSingle] = useState<ExperimentSingle>()
  const [events, setEvents] = useState<Event[]>([])

  const fetchExperiment = () => {
    api.experiments
      .single(uuid!)
      .then(({ data }) => setSingle(data))
      .catch(console.error)
  }

  useEffect(() => {
    fetchExperiment()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    const fetchEvents = () => {
      api.events
        .events({ object_id: uuid, limit: 999 })
        .then(({ data }) => setEvents(data))
        .catch(console.error)
        .finally(() => {
          setLoading(false)
        })
    }

    if (single) {
      fetchEvents()
    }
  }, [uuid, single])

  return (
    <>
      <Grow in={!loading} style={{ transformOrigin: '0 0 0' }}>
        <div>
          <Grid container>
            <Grid item xs={12} lg={6} sx={{ pr: 3 }}>
              <Paper sx={{ display: 'flex', flexDirection: 'column', height: 600 }}>
                <PaperTop title={T('events.title')} boxProps={{ mb: 3 }} />
                <Box flex={1} overflow="scroll">
                  <EventsTimeline events={events} />
                </Box>
              </Paper>
            </Grid>
          </Grid>
        </div>
      </Grow>

      {loading && <Loading />}
    </>
  )
}
