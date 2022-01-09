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
import { Box, IconButton, Typography } from '@mui/material'
import DateTime, { format } from 'lib/luxon'

import { Archive } from 'api/archives.type'
import ArchiveOutlinedIcon from '@mui/icons-material/ArchiveOutlined'
import { CatchingPokemon } from '@mui/icons-material'
import DeleteOutlinedIcon from '@mui/icons-material/DeleteOutlined'
import { Experiment } from 'api/experiments.type'
import Paper from '@ui/mui-extends/esm/Paper'
import PauseCircleOutlineIcon from '@mui/icons-material/PauseCircleOutline'
import PlayCircleOutlineIcon from '@mui/icons-material/PlayCircleOutline'
import { Schedule } from 'api/schedules.type'
import Space from '@ui/mui-extends/esm/Space'
import StatusLabel from 'components/StatusLabel'
import T from 'components/T'
import { truncate } from 'lib/utils'
import { useIntl } from 'react-intl'
import { useNavigate } from 'react-router-dom'
import { useStoreSelector } from 'store'

interface ObjectListItemProps {
  type?: 'schedule' | 'experiment' | 'archive'
  archive?: 'workflow' | 'schedule' | 'experiment'
  data: Schedule | Experiment | Archive
  onSelect: (info: { uuid: uuid; title: string; description: string; action: string }) => void
}

const ObjectListItem: React.FC<ObjectListItemProps> = ({ data, type = 'experiment', archive, onSelect }) => {
  const navigate = useNavigate()
  const intl = useIntl()

  const { lang } = useStoreSelector((state) => state.settings)

  const handleInspect = () => () => {
    navigate(`/experiments/${data.uid}/inspect`)
  }

  const handleAction = (action: string) => (event: React.MouseEvent<HTMLSpanElement>) => {
    event.stopPropagation()

    switch (action) {
      case 'archive':
        onSelect({
          title: `${T('archives.single', intl)} ${data.name}`,
          description: T(`${type}s.deleteDesc`, intl),
          action,
          uuid: data.uid,
        })

        return
      case 'pause':
        onSelect({
          title: `${T('common.pause', intl)} ${data.name}`,
          description: T('experiments.pauseDesc', intl),
          action,
          uuid: data.uid,
        })

        return
      case 'start':
        onSelect({
          title: `${T('common.start', intl)} ${data.name}`,
          description: T('experiments.startDesc', intl),
          action,
          uuid: data.uid,
        })

        return
      case 'delete':
        onSelect({
          title: `${T('common.delete', intl)} ${data.name}`,
          description: T('archives.deleteDesc', intl),
          action,
          uuid: data.uid,
        })

        return
      default:
        return
    }
  }

  const handleJumpTo = () => {
    let path
    switch (type) {
      case 'schedule':
      case 'experiment':
        path = `/${type}s/${data.uid}`
        break
      case 'archive':
        path = `/archives/${data.uid}?kind=${archive!}`
        break
    }

    navigate(path)
  }

  const Actions = () => (
    <Space direction="row" justifyContent="end" alignItems="center">
      <Typography variant="body2" title={format(data.created_at)}>
        {T('table.created')}{' '}
        {DateTime.fromISO(data.created_at, {
          locale: lang,
        }).toRelative()}
      </Typography>
      {(type === 'schedule' || type === 'experiment') &&
        ((data as Experiment).status === 'paused' ? (
          <IconButton color="primary" title={T('common.start', intl)} size="small" onClick={handleAction('start')}>
            <PlayCircleOutlineIcon />
          </IconButton>
        ) : (data as Experiment).status !== 'finished' ? (
          <IconButton color="primary" title={T('common.pause', intl)} size="small" onClick={handleAction('pause')}>
            <PauseCircleOutlineIcon />
          </IconButton>
        ) : null)}
      {type !== 'archive' && (
        <IconButton color="primary" title={T('archives.single', intl)} size="small" onClick={handleAction('archive')}>
          <ArchiveOutlinedIcon />
        </IconButton>
      )}
      {type === 'archive' && (
        <IconButton color="primary" title={T('common.delete', intl)} size="small" onClick={handleAction('delete')}>
          <DeleteOutlinedIcon />
        </IconButton>
      )}
      <IconButton color="primary" title={T('common.inspect', intl)} size="small" onClick={handleInspect()}>
        <CatchingPokemon />
      </IconButton>
    </Space>
  )

  return (
    <Paper
      sx={{
        p: 0,
        ':hover': {
          bgcolor: 'action.hover',
          cursor: 'pointer',
        },
      }}
      // onClick={handleJumpTo}
    >
      <Box display="flex" justifyContent="space-between" alignItems="center" p={3}>
        <Space direction="row" alignItems="center">
          {type !== 'archive' && <StatusLabel status={(data as Experiment).status} />}
          <Typography component="div" title={data.name}>
            {truncate(data.name)}
          </Typography>
          <Typography component="div" variant="body2" color="textSecondary" title={data.uid}>
            {truncate(data.uid)}
          </Typography>
        </Space>

        <Actions />
      </Box>
    </Paper>
  )
}

export default ObjectListItem
