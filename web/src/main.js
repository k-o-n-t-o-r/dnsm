import { mount } from 'svelte'
import './styles/theme.css'
import './styles/components.css'
import App from './App.svelte'

const app = mount(App, {
  target: document.getElementById('app'),
})

export default app
