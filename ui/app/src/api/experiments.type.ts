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
import { ExperimentKind } from 'components/NewExperiment/types'

export interface StatusOfExperiments {
  injecting: number
  running: number
  finished: number
  paused: number
}

export interface Experiment {
  is: 'experiment'
  uid: uuid
  kind: ExperimentKind
  namespace: string
  name: string
  created_at: string
  // FIXME: support keyof in ts-interface-builder
  status: 'injecting' | 'running' | 'finished' | 'paused'
}

export interface ExperimentSingle extends Experiment {
  failed_message: string
  kube_object: any
}

export interface ObserveExpTC {
  src: string
  dst: string
  ts: string
  raw: string
}
export interface ObserveExp {
  tc: string[]
  func: string[]
}
