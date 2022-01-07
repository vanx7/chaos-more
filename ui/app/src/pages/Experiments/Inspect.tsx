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

import { Box, Button, Grid, Grow, Tab, Tabs, TextareaAutosize, Typography } from '@mui/material'
import { setAlert, setConfirm } from 'slices/globalStatus'
import { useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'

import { Event } from 'api/events.type'
import EventsTimeline from 'components/EventsTimeline'
import { ExperimentSingle } from 'api/experiments.type'
import Loading from '@ui/mui-extends/esm/Loading'
import { LoadingButton } from '@mui/lab'
import ObjectConfiguration from 'components/ObjectConfiguration'
import Observe from './observe'
import Paper from '@ui/mui-extends/esm/Paper'
import PaperTop from '@ui/mui-extends/esm/PaperTop'
import PauseCircleOutlineIcon from '@mui/icons-material/PauseCircleOutline'
import PlayCircleOutlineIcon from '@mui/icons-material/PlayCircleOutline'
import Space from '@ui/mui-extends/esm/Space'
import SyncIcon from '@mui/icons-material/Sync'
import T from 'components/T'
import api from 'api'
import loadable from '@loadable/component'
import { useIntl } from 'react-intl'
import { useStoreDispatch } from 'store'
import yaml from 'js-yaml'

const YAMLEditor = loadable(() => import('components/YAMLEditor'))

interface TabPanelProps {
  children?: React.ReactNode
  dir?: string
  index: number
  value: number
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`full-width-tabpanel-${index}`}
      aria-labelledby={`full-width-tab-${index}`}
      {...other}
    >
      {value === index && (
        <Box sx={{ p: 3 }}>
          <Typography>{children}</Typography>
        </Box>
      )}
    </div>
  )
}

function a11yProps(index: number) {
  return {
    id: `full-width-tab-${index}`,
    'aria-controls': `full-width-tabpanel-${index}`,
  }
}

export default function Single() {
  const navigate = useNavigate()
  const { uuid } = useParams()

  const intl = useIntl()

  const dispatch = useStoreDispatch()

  const [loading, setLoading] = useState(true)
  const [single, setSingle] = useState<ExperimentSingle>()
  const [events, setEvents] = useState<Event[]>([])
  const [value, setValue] = useState(1)
  const [logs, setLogs] = useState('')
  const [logLoading, setLogLoading] = useState(false)

  const handlePullLog = () => {
    setLogLoading(true)
    api.experiments
      .log(uuid!)
      .then(({ data }) => setLogs(data))
      .catch(console.error)
      .finally(() => {
        setLogLoading(false)
      })
  }

  useEffect(() => {
    handlePullLog()
  }, [uuid])

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

  const handleSelect = (action: string) => () => {
    switch (action) {
      case 'archive':
        dispatch(
          setConfirm({
            title: `${T('archives.single', intl)} ${single!.name}`,
            description: T('experiments.deleteDesc', intl),
            handle: handleAction('archive'),
          })
        )

        break
      case 'pause':
        dispatch(
          setConfirm({
            title: `${T('common.pause', intl)} ${single!.name}`,
            description: T('experiments.pauseDesc', intl),
            handle: handleAction('pause'),
          })
        )

        break
      case 'start':
        dispatch(
          setConfirm({
            title: `${T('common.start', intl)} ${single!.name}`,
            description: T('experiments.startDesc', intl),
            handle: handleAction('start'),
          })
        )

        break
    }
  }

  const handleAction = (action: string) => () => {
    let actionFunc: any

    switch (action) {
      case 'archive':
        actionFunc = api.experiments.del

        break
      case 'pause':
        actionFunc = api.experiments.pause

        break
      case 'start':
        actionFunc = api.experiments.start

        break
      default:
        actionFunc = null
    }

    if (actionFunc) {
      actionFunc(uuid)
        .then(() => {
          dispatch(
            setAlert({
              type: 'success',
              message: T(`confirm.success.${action}`, intl),
            })
          )

          if (action === 'archive') {
            navigate('/experiments')
          }

          if (action === 'pause' || action === 'start') {
            setTimeout(fetchExperiment, 300)
          }
        })
        .catch(console.error)
    }
  }

  return (
    <div>
      <Tabs
        value={value}
        onChange={(_, v) => setValue(v)}
        indicatorColor="secondary"
        textColor="inherit"
        variant="fullWidth"
      >
        <Tab label={T('common.overview')} {...a11yProps(0)} />
        <Tab label={T('experiments.operation')} {...a11yProps(1)} />
        <Tab label={T('experiments.inspect')} {...a11yProps(2)} />
      </Tabs>
      <TabPanel value={value} index={0}>
        <Grow in={!loading} style={{ transformOrigin: '0 0 0' }}>
          <div>
            <Space spacing={6}>
              <Paper>{single && <ObjectConfiguration config={single} />}</Paper>

              <Grid container>
                <Grid item xs={12} lg={6} sx={{ pr: 3 }}>
                  <Paper sx={{ display: 'flex', flexDirection: 'column', height: 600 }}>
                    <PaperTop title={T('events.title')} boxProps={{ mb: 3 }} />
                    <Box flex={1} overflow="scroll">
                      <EventsTimeline events={events} />
                    </Box>
                  </Paper>
                </Grid>
                <Grid item xs={12} lg={6} sx={{ pl: 3 }}>
                  <Paper sx={{ height: 600, p: 0 }}>
                    {single && (
                      <Space display="flex" flexDirection="column" height="100%">
                        <PaperTop title={T('common.definition')} boxProps={{ p: 4.5, pb: 0 }} />
                        <Box flex={1}>
                          <YAMLEditor name={single.name} data={yaml.dump(single.kube_object)} download />
                        </Box>
                      </Space>
                    )}
                  </Paper>
                </Grid>
              </Grid>
            </Space>
          </div>
        </Grow>
      </TabPanel>
      <TabPanel value={value} index={1}>
        <Space direction="row">
          {single?.status === 'paused' ? (
            <Button
              variant="outlined"
              size="small"
              startIcon={<PlayCircleOutlineIcon />}
              onClick={handleSelect('start')}
            >
              {T('common.start')}
            </Button>
          ) : (
            <Button
              variant="outlined"
              size="small"
              startIcon={<PauseCircleOutlineIcon />}
              onClick={handleSelect('pause')}
            >
              {T('common.pause')}
            </Button>
          )}
          <LoadingButton
            loading={logLoading}
            variant="outlined"
            startIcon={<SyncIcon />}
            onClick={() => handlePullLog()}
          >
            {T('common.pullLog')}
          </LoadingButton>
        </Space>
        <Box>
          <br />
          <TextareaAutosize maxRows={4} defaultValue={logs} style={{ width: '100%', height: '70vh' }} />
        </Box>
      </TabPanel>
      <TabPanel value={value} index={2}>
        <Observe />
      </TabPanel>
      {loading && <Loading />}
    </div>
  )
}
