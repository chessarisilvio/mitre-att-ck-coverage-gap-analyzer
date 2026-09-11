# MITRE ATT&CK Coverage Gap Analyzer - Architettura Auto-tuning

## 1. Panoramica Sistema

### 1.1 Obiettivo
Sviluppare un sistema di auto-tuning dinamico per ottimizzare le performance del MITRE ATT&CK Coverage Gap Analyzer, monitorando in tempo reale risorse GPU/CPU e adattando i parametri di elaborazione.

### 1.2 Componenti Principali
- **Monitor Module** (`src/monitor.py`): Monitoraggio VRAM, CPU, temperature GPU
- **Optimizer Module** (`src/optimizer.py`): Algoritmo di ottimizzazione per parametri
- **CLI Integration**: Interfaccia utente con Typer per controlli

## 2. Architettura Moduli

### 2.1 Modulo Monitor (src/monitor.py)

#### Funzionalità
- Monitoraggio VRAM in tempo reale tramite `nvidia-smi`
- Monitoraggio CPU usage e load average
- Monitoraggio temperature GPU Tesla P40
- Raccolta metriche con intervallo configurabile

#### Interfaccia
```python
class SystemMonitor:
    def __init__(self, interval: float = 1.0):
        """Initialize monitor with sampling interval."""
        
    def get_gpu_stats(self) -> Dict[str, Any]:
        """Returns GPU memory used/total, temperature, utilization."""
        
    def get_cpu_stats(self) -> Dict[str, Any]:
        """Returns CPU usage percentage, load average."""
        
    def start_monitoring(self, callback: Callable) -> Thread:
        """Start continuous monitoring in background thread."""
```

#### Metriche Raccolte
- `gpu_memory_used`: MB usati sulla GPU
- `gpu_memory_total`: MB totali disponibili
- `gpu_utilization`: % utilizzo GPU
- `gpu_temperature`: Celsius
- `cpu_percent`: % utilizzo CPU
- `cpu_load_avg`: Load average 1/5/15 min

### 2.2 Modulo Optimizer (src/optimizer.py)

#### Funzionalità
- Analisi delle performance in base a metriche sistema
- Calcolo parametri ottimali per elaborazione
- Suggerimenti per riduzione carico quando necessario

#### Interfaccia
```python
class PerformanceOptimizer:
    def __init__(self, monitor: SystemMonitor, thresholds: Dict[str, float]):
        """Initialize optimizer with monitor and thresholds."""
        
    def evaluate_performance(self) -> Dict[str, Any]:
        """Evaluate current system performance state."""
        
    def suggest_optimizations(self) -> List[Dict[str, Any]]:
        """Suggest optimization actions based on current metrics."""
        
    def calculate_optimal_batch_size(self, base_batch: int) -> int:
        """Calculate optimal batch size based on available VRAM."""
```

#### Algoritmo di Ottimizzazione
1. **Valutazione Stato Sistema**
   - Se VRAM > 90%: riduci batch size del 25%
   - Se VRAM > 95%: riduci batch size del 50%
   - Se temperature > 80°C: riduci carico del 20%
   - Se CPU > 90%: riduci parallelismo

2. **Calcolo Batch Size Dinamico**
   ```
   available_vram = total_vram - used_vram
   optimal_batch = base_batch * (available_vram / total_vram) * 0.8
   ```

3. **Priorità Azioni**
   - CRITICAL: VRAM > 95% o temp > 85°C
   - HIGH: VRAM > 90% o temp > 80°C
   - MEDIUM: VRAM > 85%
   - LOW: VRAM > 80%

### 2.3 Integrazione CLI

#### Nuovi Comandi
```bash
# Monitoraggio in tempo reale
mitre-gap-analyzer monitor --interval 2.0 --duration 60

# Analisi con ottimizzazione automatica
mitre-gap-analyzer analyze --auto-tune --mitre-path data/enterprise-attack.json --coverage-path data/coverage.csv

# Report con statistiche sistema
mitre-gap-analyzer report --with-system-stats
```

#### Opzioni CLI
- `--auto-tune`: Abilita ottimizzazione automatica
- `--monitor-interval`: Intervallo campionamento metriche (default: 1.0s)
- `--vram-threshold`: Soglia VRAM % per warning (default: 85)
- `--temp-threshold`: Soglia temperatura °C per warning (default: 80)

## 3. Flusso Dati

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   MITRE Data    │────▶│   Coverage Map  │────▶│   Gap Engine    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                              │                         │
                              ▼                         ▼
                       ┌─────────────────┐     ┌─────────────────┐
                       │  CoverageLoader │     │  GapEngine    │
                       └─────────────────┘     └─────────────────┘
                              │                         │
                              ▼                         ▼
                       ┌─────────────────────────────────────────┐
                       │         System Monitor (Background)     │
                       │  - GPU VRAM, CPU, Temperature           │
                       │  - Sampling ogni N secondi              │
                       └─────────────────────────────────────────┘
                              │
                              ▼
                       ┌─────────────────────────────────────────┐
                       │         Performance Optimizer           │
                       │  - Analizza metriche                    │
                       │  - Suggerisce ottimizzazioni          │
                       │  - Calcola batch size ottimale         │
                       └─────────────────────────────────────────┘
                              │
                              ▼
                       ┌─────────────────────────────────────────┐
                       │         Report Generator                │
                       │  - Genera report con stats sistema     │
                       │  - Include raccomandazioni ottimiz.    │
                       └─────────────────────────────────────────┘
```

## 4. Configurazione

### 4.1 File di Configurazione (config.yaml)
```yaml
monitoring:
  interval_seconds: 1.0
  vram_warning_threshold: 85
  vram_critical_threshold: 95
  temp_warning_threshold: 80
  temp_critical_threshold: 85

optimization:
  auto_tune_enabled: true
  batch_size_adjustment: true
  max_concurrent_processes: 4

output:
  include_system_stats: true
  stats_sampling_duration: 5.0
```

### 4.2 Thresholds Predefiniti
| Metric | Warning | Critical |
|--------|---------|----------|
| VRAM Usage | 85% | 95% |
| GPU Temperature | 80°C | 85°C |
| CPU Usage | 90% | 95% |

## 5. Strutture Dati

### 5.1 SystemStats
```python
@dataclass
class SystemStats:
    timestamp: datetime
    gpu_memory_used: int
    gpu_memory_total: int
    gpu_utilization: float
    gpu_temperature: float
    cpu_percent: float
    cpu_load_avg: Tuple[float, float, float]
```

### 5.2 OptimizationSuggestion
```python
@dataclass
class OptimizationSuggestion:
    priority: str  # CRITICAL, HIGH, MEDIUM, LOW
    metric: str    # vram, temperature, cpu
    current_value: float
    threshold: float
    suggested_action: str
    impact: str    # reduction_percentage
```

## 6. Testing

### 6.1 Test Unitari
- `tests/test_monitor.py`: Test del modulo monitor
- `tests/test_optimizer.py`: Test del modulo optimizer

### 6.2 Test End-to-End
- Verifica raccolta metriche in ambiente con GPU
- Test ottimizzazione batch size
- Test report con system stats

## 7. Considerazioni GPU Tesla P40

### 7.1 Specifiche Hardware
- VRAM: 24 GB GDDR5X
- Max temperature operativa: 64°C (soglia throttle: 89°C)
- Compute capability: 6.1

### 7.2 Parametri Consigliati
- Batch size massimo: 4096 (come configurato in modello)
- Context size: 131072 token
- GPU layers: Dinamico in base a VRAM disponibile

### 7.3 Formula Calcolo GPU Layers
```
available_memory = total_vram - used_vram - safety_margin(2GB)
gpu_layers = min(max_layers, (available_memory / 0.5) * layer_factor)
```

## 8. Estensioni Future

### 8.1 Possibili Miglioramenti
- Integrazione con Prometheus/Grafana per monitoring
- Alert via Telegram quando soglie superate
- Auto-scaling per processi paralleli
- Profiling dettagliato per ogni fase di analisi

### 8.2 Integrazione con Altri Tool
- Supporto per altri formati MITRE (Enterprise, Mobile, ICS)
- Integrazione con Elastic Stack per visualizzazione
- API REST per monitoraggio remoto

## 9. Implementazione Dettagliata

### 9.1 Monitor Module (monitor.py)

#### Struttura Classi
```python
class SystemMonitor:
    - __init__(interval: float = 1.0)
    - get_gpu_stats() -> Dict[str, Any]
    - get_cpu_stats() -> Dict[str, Any]
    - get_system_stats() -> SystemStats
    - start_monitoring(callback) -> Thread
    - stop_monitoring()
    - get_stats_history(max_samples) -> List[SystemStats]
    - get_average_stats(duration) -> Dict[str, float]

class SystemStats (dataclass):
    - timestamp: datetime
    - gpu_memory_used: int
    - gpu_memory_total: int
    - gpu_utilization: float
    - gpu_temperature: float
    - cpu_percent: float
    - cpu_load_avg: Tuple[float, float, float]
```

#### Funzionalità Specifiche
- **Sampling periodico**: Ogni N secondi (configurabile)
- **Raccolta metriche**: GPU via nvidia-smi, CPU via /proc
- **History buffer**: Memorizza ultimi N campioni
- **Callback system**: Notifica quando superate soglie

### 9.2 Optimizer Module (optimizer.py)

#### Struttura Classi
```python
class PerformanceOptimizer:
    - __init__(monitor, thresholds)
    - evaluate_performance() -> Dict[str, Any]
    - suggest_optimizations() -> List[OptimizationSuggestion]
    - calculate_optimal_batch_size(base_batch) -> int
    - calculate_gpu_layers(available_memory) -> int
    - should_pause_processing() -> bool
    - get_optimization_report() -> Dict[str, Any]

class OptimizationSuggestion (dataclass):
    - priority: Priority
    - metric: str
    - current_value: float
    - threshold: float
    - suggested_action: str
    - impact: str
```

#### Algoritmo di Ottimizzazione
1. **Valutazione continua**: Monitora metriche ogni campionamento
2. **Classificazione priorità**:
   - CRITICAL: VRAM > 95% o temp > 85°C
   - HIGH: VRAM > 90% o temp > 80°C
   - MEDIUM: VRAM > 85%
   - LOW: VRAM > 80%
3. **Azioni correttive**:
   - Riduzione batch size (25-50%)
   - Riduzione parallelismo
   - Pausa elaborazione se critico

### 9.3 CLI Integration

#### Nuovi Comandi
```bash
# Monitoraggio in tempo reale
mitre-gap-analyzer monitor --interval 2.0 --duration 60

# Analisi con ottimizzazione automatica
mitre-gap-analyzer analyze --auto-tune --mitre-path data/enterprise-attack.json

# Report con statistiche sistema
mitre-gap-analyzer report --with-system-stats
```

#### Opzioni Aggiuntive
- `--auto-tune`: Abilita ottimizzazione automatica
- `--monitor-interval`: Intervallo campionamento (default: 1.0s)
- `--vram-threshold`: Soglia VRAM % (default: 85)
- `--temp-threshold`: Soglia temperatura °C (default: 80)

## 10. Testing Completo

### 10.1 Test Unitari Monitor
- Test inizializzazione con intervalli diversi
- Test recupero GPU stats (successo/errore)
- Test recupero CPU stats
- Test raccolta history
- Test callback system

### 10.2 Test Unitari Optimizer
- Test inizializzazione con thresholds
- Test valutazione performance
- Test suggerimenti ottimizzazione (VRAM warning/critical)
- Test calcolo batch size ottimale
- Test calcolo GPU layers

### 10.3 Test End-to-End
- Test integrazione completa monitor + optimizer
- Test CLI con opzioni auto-tune
- Test report con system stats

### 10.4 Test Hardware Specifici
- Test su sistema con GPU Tesla P40
- Test gestione memoria 24GB
- Test temperatura (soglia 64°C operativa)
- Test batch size massimo 4096