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

import { Box, Grid, Grow, List, ListItem, ListItemText, TextareaAutosize } from '@mui/material'
import { useEffect, useState } from 'react'

import Loading from '@ui/mui-extends/esm/Loading'
import { ObserveExp } from 'api/experiments.type'
import Paper from '@ui/mui-extends/esm/Paper'
import PaperTop from '@ui/mui-extends/esm/PaperTop'
import T from 'components/T'
import api from 'api'
import { useParams } from 'react-router-dom'

export default function Observe() {
  const { uuid } = useParams()

  const [loading, setLoading] = useState(true)

  const [data, setData] = useState<ObserveExp>()

  const fetchObserve = () => {
    api.experiments
      .observe(uuid!)
      .then(({ data }) => setData(data))
      .catch(console.error)
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    fetchObserve()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <>
      <Grow in={!loading} style={{ transformOrigin: '0 0 0' }}>
        <div>
          <Grid container>
            <Grid item xs={12} lg={6} sx={{ pr: 3 }}>
              <Paper sx={{ display: 'flex', flexDirection: 'column', height: 600 }}>
                <PaperTop title={T('events.title')} boxProps={{ mb: 3 }} />
                <Box flex={1} overflow="scroll">
                  <TextareaAutosize maxRows={4} defaultValue={data?.tc} style={{ width: '100%', height: '70vh' }} />
                  {/* <List sx={{ width: '100%', maxWidth: 360, bgcolor: 'background.paper' }}>
                    {data?.tc.map((value) => {
                      return (
                        <ListItem disablePadding>
                          <ListItemText primary={value} />
                        </ListItem>
                      )
                    })}
                  </List> */}
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
