<template>
  <div class="screenshots-tab">
    <!-- 搜索和过滤栏 -->
    <div class="toolbar">
      <el-input
        v-model="searchQuery"
        :placeholder="t('asset.screenshotsTab.searchPlaceholder')"
        clearable
        class="search-input"
        @input="handleSearch"
      >
        <template #prefix>
          <el-icon><Search /></el-icon>
        </template>
      </el-input>
      <el-button @click="showFilters = !showFilters">
        <el-icon><Filter /></el-icon>
        {{ t('asset.screenshotsTab.filters') }}
      </el-button>
      <el-button @click="refreshData">
        <el-icon><Refresh /></el-icon>
        {{ t('asset.screenshotsTab.refresh') }}
      </el-button>
    </div>

    <!-- 高级过滤器 -->
    <div v-if="showFilters" class="filters-panel">
      <el-form :inline="true">
        <el-form-item :label="t('asset.screenshotsTab.statusCodes')">
          <el-select v-model="filters.statusCodes" multiple :placeholder="t('asset.screenshotsTab.selectStatus')" clearable filterable>
            <el-option
              v-for="code in filterOptions.statusCodes"
              :key="code"
              :label="code"
              :value="code"
            />
          </el-select>
        </el-form-item>
        <el-form-item :label="t('asset.screenshotsTab.timeRange')">
          <el-select v-model="filters.timeRange" :placeholder="t('asset.screenshotsTab.selectTime')" clearable>
            <el-option :label="t('asset.screenshotsTab.allTime')" value="all" />
            <el-option :label="t('asset.screenshotsTab.last24h')" value="24h" />
            <el-option :label="t('asset.screenshotsTab.last7d')" value="7d" />
            <el-option :label="t('asset.screenshotsTab.last30d')" value="30d" />
          </el-select>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="applyFilters">{{ t('asset.screenshotsTab.apply') }}</el-button>
          <el-button @click="resetFilters">{{ t('asset.screenshotsTab.reset') }}</el-button>
        </el-form-item>
      </el-form>
    </div>

    <!-- 截图网格 -->
    <div v-loading="loading" class="screenshots-grid">
      <div
        v-for="item in screenshots"
        :key="item.id"
        class="screenshot-card"
        @click="viewDetails(item)"
      >
        <!-- 截图图片 -->
        <div 
          class="screenshot-image-container"
          @mouseenter="showPreview(item, $event)"
          @mouseleave="hidePreview"
        >
          <img
            v-if="item.screenshot"
            :src="formatScreenshotUrl(item.screenshot)"
            :alt="item.name"
            class="screenshot-image"
            @error="handleScreenshotError"
          />
          <div v-else class="no-screenshot">
            <el-icon><Picture /></el-icon>
            <span>{{ t('asset.screenshotsTab.noScreenshot') }}</span>
          </div>
          
          <!-- 状态标签 -->
          <div class="screenshot-status">
            <el-tag :type="getStatusType(item.status)" size="small">
              {{ item.status }}
            </el-tag>
          </div>
        </div>

        <!-- 截图信息 -->
        <div class="screenshot-info">
          <div class="screenshot-title">
            <el-icon class="icon"><Monitor /></el-icon>
            <span class="name">{{ item.name }}</span>
            <span class="port">:{{ item.port }}</span>
          </div>
          
          <div class="screenshot-meta">
            <span class="page-title">{{ item.title || t('asset.screenshotsTab.noTitle') }}</span>
          </div>
          
          <div class="screenshot-details">
            <span class="ip">{{ item.ip }}</span>
            <span class="time">{{ item.lastUpdated }}</span>
          </div>
          
          <!-- 技术标签 -->
          <div v-if="item.technologies && item.technologies.length" class="tech-tags">
            <el-tag
              v-for="tech in item.technologies.slice(0, 3)"
              :key="tech.name"
              size="small"
              class="tech-tag"
            >
              {{ tech.name }}
            </el-tag>
            <el-tag v-if="item.technologies.length > 3" size="small" type="info">
              +{{ item.technologies.length - 3 }}
            </el-tag>
          </div>
        </div>
      </div>
    </div>

    <!-- 空状态 -->
    <div v-if="!loading && screenshots.length === 0" class="empty-state">
      <el-empty description="暂无截图数据" />
    </div>

    <!-- 分页 -->
    <el-pagination
      v-if="screenshots.length > 0"
      v-model:current-page="currentPage"
      v-model:page-size="pageSize"
      :total="total"
      :page-sizes="[5, 10, 20, 50, 100]"
      layout="total, sizes, prev, pager, next"
      class="pagination"
      @size-change="loadData"
      @current-change="loadData"
    />

    <!-- 截图详情抽屉 - 使用共享组件 -->
    <AssetDetailDrawer
      v-model:visible="showDetailsDialog"
      :asset="selectedItem"
      @preview-show="showPreview"
      @preview-hide="hidePreview"
    />
    
    <!-- 图片预览浮层 -->
    <Teleport to="body">
      <Transition name="preview-fade">
        <div
          v-if="previewVisible"
          class="screenshot-preview-overlay"
          :style="{
            left: previewPosition.x + 'px',
            top: previewPosition.y + 'px',
            width: previewSize.width + 'px',
            maxHeight: previewSize.height + 'px'
          }"
        >
          <div class="preview-container">
            <img
              :src="previewImage"
              alt="Screenshot Preview"
              class="preview-image"
              @error="handleScreenshotError"
            />
          </div>
        </div>
      </Transition>
    </Teleport>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { debounce } from 'lodash-es'
import {
  Search,
  Filter,
  Refresh,
  Picture,
  Monitor,
  Link,
  Box,
  Right
} from '@element-plus/icons-vue'
import { getScreenshots, getAssetFilterOptions, getAssetHistory, getAssetExposures, getAssetDirScans, getAssetVulnScans } from '@/api/asset'
import { formatScreenshotUrl, handleScreenshotError } from '@/utils/screenshot'
import AssetDetailDrawer from '@/components/asset/AssetDetailDrawer.vue'
import ScanResultHistory from '@/components/ScanResultHistory.vue'

const { t } = useI18n()

const loading = ref(false)
const searchQuery = ref('')
const showFilters = ref(false)
const currentPage = ref(1)
const pageSize = ref(10)
const total = ref(0)
const screenshots = ref([])
const showDetailsDialog = ref(false)
const selectedItem = ref(null)
const activeDetailTab = ref('overview')
const filters = ref({
  statusCodes: [],
  timeRange: 'all'
})

// Directory scans state
const dirScansLoading = ref(false)
const dirScans = ref([])
const dirScansTotal = ref(0)
const dirScansPage = ref(1)
const dirScansPageSize = ref(100)

// Vulnerability scans state
const vulnScansLoading = ref(false)
const vulnScans = ref([])
const vulnScansTotal = ref(0)
const vulnScansPage = ref(1)
const vulnScansPageSize = ref(50)
const vulnScansError = ref(false)

// Directory scans error state
const dirScansError = ref(false)

// 过滤器选项（从后端动态加载）
const filterOptions = ref({
  statusCodes: []
})

// 图片预览
const previewVisible = ref(false)
const previewImage = ref('')
const previewPosition = ref({ x: 0, y: 0 })
const previewSize = ref({ width: 500, height: 400 })

const showPreview = (item, event) => {
  if (!item.screenshot) return
  
  previewImage.value = formatScreenshotUrl(item.screenshot)
  previewVisible.value = true
  
  // 计算预览位置
  const rect = event.currentTarget.getBoundingClientRect()
  
  // 检查是否在抽屉或对话框中
  const isInDrawer = event.currentTarget.closest('.el-drawer__body') !== null
  const isInDialog = event.currentTarget.closest('.el-dialog__body') !== null
  const isInDetailView = isInDrawer || isInDialog
  
  let previewWidth, previewHeight, padding
  
  if (isInDetailView) {
    // 在详情视图中，使用更大的预览尺寸
    previewWidth = Math.min(800, window.innerWidth * 0.5)
    previewHeight = Math.min(900, window.innerHeight * 0.8)
    padding = 30
  } else {
    // 在列表视图中，使用较小的预览尺寸
    previewWidth = 500
    previewHeight = 400
    padding = 20
  }
  
  previewSize.value = { width: previewWidth, height: previewHeight }
  
  // 默认显示在右侧
  let x = rect.right + padding
  let y = rect.top
  
  // 如果右侧空间不够，显示在左侧
  if (x + previewWidth > window.innerWidth) {
    x = rect.left - previewWidth - padding
  }
  
  // 如果下方空间不够，向上调整
  if (y + previewHeight > window.innerHeight) {
    y = window.innerHeight - previewHeight - padding
  }
  
  // 确保不超出顶部
  if (y < padding) {
    y = padding
  }
  
  // 确保不超出左侧
  if (x < padding) {
    x = padding
  }
  
  previewPosition.value = { x, y }
}

const hidePreview = () => {
  previewVisible.value = false
}

const loadData = async () => {
  loading.value = true
  try {
    const res = await getScreenshots({
      page: currentPage.value,
      pageSize: pageSize.value,
      query: searchQuery.value,
      technologies: [],
      ports: [],
      statusCodes: filters.value.statusCodes,
      timeRange: filters.value.timeRange,
      hasScreenshot: true
    })
    if (res.code === 0) {
      screenshots.value = res.list || []
      total.value = res.total || 0
    }
  } catch (error) {
    console.error('加载失败:', error)
  } finally {
    loading.value = false
  }
}

const handleSearch = debounce(() => {
  currentPage.value = 1
  loadData()
}, 300)

const refreshData = () => {
  loadData()
  ElMessage.success(t('asset.screenshotsTab.refreshSuccess'))
}

const applyFilters = () => {
  currentPage.value = 1
  loadData()
}

const resetFilters = () => {
  filters.value = {
    statusCodes: [],
    timeRange: 'all'
  }
  currentPage.value = 1
  loadData()
}

const viewDetails = async (item) => {
  selectedItem.value = {
    ...item,
    changelogs: [],
    dirScanResults: [],
    vulnScanResults: []
  }
  showDetailsDialog.value = true
  activeDetailTab.value = 'overview'
  
  // Reset directory scans pagination
  dirScansPage.value = 1
  dirScans.value = []
  dirScansTotal.value = 0
  
  // Reset vulnerability scans pagination
  vulnScansPage.value = 1
  vulnScans.value = []
  vulnScansTotal.value = 0
  
  // 异步加载变更记录和暴露面数据
  // 异步加载额外数据，忽略错误
  if (item.id) {
    // 静默加载，不阻塞UI
    loadAssetHistory(item.id).catch(() => {})
    loadAssetExposures(item.id).catch(() => {})
    loadDirScans(item.id).catch(() => {})
    loadVulnScans(item.id).catch(() => {})
  }
}

// 加载资产变更记录
const loadAssetHistory = async (assetId) => {
  try {
    const res = await getAssetHistory({
      assetId: assetId,
      limit: 50
    })
    
    if (res.code === 0 && res.list && selectedItem.value) {
      selectedItem.value.changelogs = res.list.map(item => ({
        time: formatDateTime(item.createTime),
        taskId: item.taskId,
        changes: item.changes || []
      }))
    } else {
      // API返回非0代码，静默处理
      if (selectedItem.value) {
        selectedItem.value.changelogs = []
      }
    }
  } catch (error) {
    // 静默失败，不影响用户体验
    console.debug('加载变更记录失败:', error.message)
    if (selectedItem.value) {
      selectedItem.value.changelogs = []
    }
  }
}

// 加载资产暴露面数据
const loadAssetExposures = async (assetId) => {
  try {
    const res = await getAssetExposures({
      assetId: assetId
    })
    
    if (res.code === 0 && selectedItem.value) {
      selectedItem.value.dirScanResults = (res.dirScanResults || []).map(item => ({
        url: item.url,
        path: item.path,
        status: String(item.status || ''),
        contentLength: item.contentLength,
        responseTime: 0,
        title: item.title || ''
      }))
      
      selectedItem.value.vulnScanResults = (res.vulnResults || []).map(item => ({
        id: item.id,
        name: item.name,
        severity: item.severity,
        description: item.description || '',
        cvss: item.cvss || 0,
        cve: item.cve || '',
        matchedUrl: item.matchedUrl || item.url,
        discoveredAt: item.discoveredAt || ''
      }))
    } else {
      // API返回非0代码，静默处理
      if (selectedItem.value) {
        selectedItem.value.dirScanResults = []
        selectedItem.value.vulnScanResults = []
      }
    }
  } catch (error) {
    // 静默失败，不影响用户体验
    console.debug('加载暴露面数据失败:', error.message)
    if (selectedItem.value) {
      selectedItem.value.dirScanResults = []
      selectedItem.value.vulnScanResults = []
    }
  }
}

// 加载目录扫描结果（支持分页）
const loadDirScans = async (assetId) => {
  if (!assetId) return
  
  dirScansLoading.value = true
  dirScansError.value = false
  try {
    const res = await getAssetDirScans({
      assetId: assetId,
      limit: dirScansPageSize.value,
      offset: (dirScansPage.value - 1) * dirScansPageSize.value
    })
    
    if (res.code === 0) {
      dirScans.value = res.results || []
      dirScansTotal.value = res.total || 0
      
      // 同时更新selectedItem中的数据，供共享组件使用
      if (selectedItem.value) {
        selectedItem.value.dirScanResults = res.results || []
      }
    } else {
      dirScansError.value = true
    }
  } catch (error) {
    dirScansError.value = true
    console.debug('加载目录扫描结果失败:', error.message)
    // 静默失败，不显示错误消息
    if (selectedItem.value) {
      selectedItem.value.dirScanResults = []
    }
  } finally {
    dirScansLoading.value = false
  }
}

// 处理目录扫描分页变化
const handleDirScansPageChange = (page) => {
  dirScansPage.value = page
  if (selectedItem.value?.id) {
    loadDirScans(selectedItem.value.id)
  }
}

// 处理目录扫描每页大小变化
const handleDirScansSizeChange = (size) => {
  dirScansPageSize.value = size
  dirScansPage.value = 1
  if (selectedItem.value?.id) {
    loadDirScans(selectedItem.value.id)
  }
}

// 加载漏洞扫描结果（支持分页）
const loadVulnScans = async (assetId) => {
  if (!assetId) return
  
  vulnScansLoading.value = true
  vulnScansError.value = false
  try {
    const res = await getAssetVulnScans({
      assetId: assetId,
      limit: vulnScansPageSize.value,
      offset: (vulnScansPage.value - 1) * vulnScansPageSize.value
    })
    
    if (res.code === 0) {
      vulnScans.value = res.results || []
      vulnScansTotal.value = res.total || 0
      
      // 同时更新selectedItem中的数据，供共享组件使用
      if (selectedItem.value) {
        selectedItem.value.vulnScanResults = res.results || []
      }
    } else {
      vulnScansError.value = true
    }
  } catch (error) {
    vulnScansError.value = true
    console.debug('加载漏洞扫描结果失败:', error.message)
    // 静默失败，不显示错误消息
    if (selectedItem.value) {
      selectedItem.value.vulnScanResults = []
    }
  } finally {
    vulnScansLoading.value = false
  }
}

// 处理漏洞扫描分页变化
const handleVulnScansPageChange = (page) => {
  vulnScansPage.value = page
  if (selectedItem.value?.id) {
    loadVulnScans(selectedItem.value.id)
  }
}

// 处理漏洞扫描每页大小变化
const handleVulnScansSizeChange = (size) => {
  vulnScansPageSize.value = size
  vulnScansPage.value = 1
  if (selectedItem.value?.id) {
    loadVulnScans(selectedItem.value.id)
  }
}

// 获取风险等级类型
const getRiskLevelType = (riskLevel) => {
  const level = String(riskLevel || '').toLowerCase()
  if (level === 'high' || level === 'critical') return 'danger'
  if (level === 'medium') return 'warning'
  if (level === 'low') return 'info'
  return 'info'
}

// 获取风险等级显示文本
const getRiskLevelText = (riskLevel) => {
  const level = String(riskLevel || '').toLowerCase()
  const levelMap = {
    'critical': t('asset.assetDetail.riskCritical'),
    'high': t('asset.assetDetail.riskHigh'),
    'medium': t('asset.assetDetail.riskMedium'),
    'low': t('asset.assetDetail.riskLow'),
    'info': t('asset.assetDetail.riskInfo')
  }
  return levelMap[level] || riskLevel
}

// 重试加载目录扫描
const retryLoadDirScans = () => {
  if (selectedItem.value?.id) {
    loadDirScans(selectedItem.value.id)
  }
}

// 重试加载漏洞扫描
const retryLoadVulnScans = () => {
  if (selectedItem.value?.id) {
    loadVulnScans(selectedItem.value.id)
  }
}

// 格式化日期时间
const formatDateTime = (dateStr) => {
  if (!dateStr) return ''
  const date = new Date(dateStr)
  return date.toLocaleString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  })
}

// 格式化字节大小
const formatBytes = (bytes) => {
  if (!bytes || bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i]
}

// 翻译字段名称
const translateFieldName = (field) => {
  const fieldMap = {
    'title': t('asset.field.title'),
    'service': t('asset.field.service'),
    'httpStatus': t('asset.field.httpStatus'),
    'app': t('asset.field.app'),
    'iconHash': t('asset.field.iconHash'),
    'server': t('asset.field.server'),
    'banner': t('asset.field.banner')
  }
  return fieldMap[field] || field
}

// 计算暴露面数量
const getExposuresCount = () => {
  if (!selectedItem.value) return 0
  const dirCount = selectedItem.value.dirScanResults?.length || 0
  const vulnCount = selectedItem.value.vulnScanResults?.length || 0
  return 1 + dirCount + vulnCount
}

const openInNewTab = () => {
  if (selectedItem.value) {
    const url = `http://${selectedItem.value.name}:${selectedItem.value.port}`
    window.open(url, '_blank')
  }
}

const getStatusType = (status) => {
  const statusStr = String(status || '')
  if (statusStr.startsWith('2')) return 'success'
  if (statusStr.startsWith('3')) return 'warning'
  if (statusStr.startsWith('4') || statusStr.startsWith('5')) return 'danger'
  return 'info'
}

// 加载过滤器选项
const loadFilterOptions = async () => {
  try {
    const res = await getAssetFilterOptions({
      hasScreenshot: true
    })
    
    if (res.code === 0) {
      filterOptions.value = {
        statusCodes: res.statusCodes || []
      }
    }
  } catch (error) {
    console.error('加载过滤器选项失败:', error)
  }
}

onMounted(() => {
  loadFilterOptions()
  loadData()
})
</script>

<style lang="scss" scoped>
.screenshots-tab {
  .toolbar {
    display: flex;
    gap: 12px;
    margin-bottom: 16px;
    
    .search-input {
      flex: 1;
      max-width: 400px;
    }
  }
  
  .filters-panel {
    background: hsl(var(--card));
    border: 1px solid hsl(var(--border));
    border-radius: 8px;
    padding: 16px;
    margin-bottom: 16px;
    
    :deep(.el-select) {
      min-width: 200px;
    }
  }
  
  .screenshots-grid {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 16px;
    margin-bottom: 24px;
  }
  
  .screenshot-card {
    background: hsl(var(--card));
    border: 1px solid hsl(var(--border));
    border-radius: 8px;
    overflow: hidden;
    cursor: pointer;
    transition: all 0.2s;
    
    &:hover {
      border-color: hsl(var(--primary));
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
      transform: translateY(-2px);
    }
  }
  
  .screenshot-image-container {
    position: relative;
    height: 200px;
    background: hsl(var(--muted));
    
    .screenshot-image {
      width: 100%;
      height: 100%;
      object-fit: cover;
    }
    
    .no-screenshot {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      height: 100%;
      color: hsl(var(--muted-foreground));
      
      .el-icon {
        font-size: 48px;
        margin-bottom: 8px;
      }
    }
    
    .screenshot-status {
      position: absolute;
      top: 8px;
      right: 8px;
    }
  }
  
  .screenshot-info {
    padding: 16px;
    
    .screenshot-title {
      display: flex;
      align-items: center;
      gap: 6px;
      margin-bottom: 8px;
      
      .icon {
        color: hsl(var(--muted-foreground));
      }
      
      .name {
        font-weight: 500;
        color: hsl(var(--foreground));
      }
      
      .port {
        color: hsl(var(--primary));
        font-weight: 500;
      }
    }
    
    .screenshot-meta {
      margin-bottom: 8px;
      
      .page-title {
        font-size: 13px;
        color: hsl(var(--muted-foreground));
        display: block;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
    }
    
    .screenshot-details {
      display: flex;
      justify-content: space-between;
      font-size: 12px;
      color: hsl(var(--muted-foreground));
      margin-bottom: 12px;
    }
    
    .tech-tags {
      display: flex;
      gap: 6px;
      flex-wrap: wrap;
      
      .tech-tag {
        font-size: 11px;
      }
    }
  }
  
  .empty-state {
    padding: 60px 20px;
    text-align: center;
  }
  
  .pagination {
    margin-top: 16px;
  }
  
  // 资产详情抽屉样式
  .asset-detail {
    .detail-header {
      display: grid;
      grid-template-columns: 300px 1fr;
      gap: 24px;
      margin-bottom: 24px;
      padding-bottom: 24px;
      border-bottom: 1px solid hsl(var(--border));
      
      .detail-screenshot {
        width: 100%;
        aspect-ratio: 16 / 10;
        border-radius: 8px;
        overflow: hidden;
        background: hsl(var(--muted) / 0.3);
        cursor: pointer;
        
        .detail-screenshot-img {
          width: 100%;
          height: 100%;
          object-fit: cover;
        }
        
        .detail-screenshot-placeholder {
          width: 100%;
          height: 100%;
          display: flex;
          align-items: center;
          justify-content: center;
          color: hsl(var(--muted-foreground));
          font-style: italic;
        }
      }
      
      .detail-basic-info {
        display: flex;
        flex-direction: column;
        gap: 12px;
        
        .info-row {
          display: flex;
          align-items: center;
          gap: 12px;
          
          .info-label {
            font-weight: 500;
            color: hsl(var(--muted-foreground));
            min-width: 60px;
          }
          
          .info-value {
            color: hsl(var(--foreground));
            word-break: break-all;
            
            &.link {
              color: hsl(var(--primary));
              text-decoration: none;
              
              &:hover {
                text-decoration: underline;
              }
            }
          }
        }
      }
    }
    
    .detail-tabs {
      :deep(.el-tabs__item) {
        .tab-badge {
          margin-left: 8px;
        }
      }
    }
    
    .tab-content {
      padding: 16px 0;
      
      .section {
        margin-bottom: 24px;
        
        &:last-child {
          margin-bottom: 0;
        }
        
        .section-title {
          font-size: 16px;
          font-weight: 600;
          color: hsl(var(--foreground));
          margin: 0 0 16px 0;
        }
        
        .info-grid {
          display: grid;
          grid-template-columns: repeat(2, 1fr);
          gap: 16px;
          
          .info-item {
            display: flex;
            gap: 12px;
            
            .item-label {
              font-weight: 500;
              color: hsl(var(--muted-foreground));
              min-width: 80px;
            }
            
            .item-value {
              color: hsl(var(--foreground));
              word-break: break-all;
            }
          }
        }
        
        .code-block {
          background: hsl(var(--muted) / 0.3);
          border: 1px solid hsl(var(--border));
          border-radius: 6px;
          padding: 16px;
          overflow-x: auto;
          
          &.small {
            padding: 12px;
          }
          
          pre {
            margin: 0;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            line-height: 1.6;
            color: hsl(var(--foreground));
            white-space: pre-wrap;
            word-break: break-all;
          }
        }
      }
      
      .exposure-item {
        padding: 16px;
        background: hsl(var(--card));
        border: 1px solid hsl(var(--border));
        border-radius: 8px;
        
        .exposure-header {
          display: flex;
          align-items: center;
          gap: 12px;
          margin-bottom: 16px;
          
          .exposure-service {
            font-weight: 500;
            color: hsl(var(--foreground));
          }
        }
        
        .exposure-details {
          display: flex;
          flex-direction: column;
          gap: 12px;
          
          .detail-item {
            .detail-label {
              font-weight: 500;
              color: hsl(var(--muted-foreground));
              margin-right: 8px;
            }
            
            .detail-value {
              color: hsl(var(--foreground));
            }
          }
        }
      }
      
      .tech-list-detail {
        display: flex;
        flex-direction: column;
        gap: 12px;
        
        .tech-item-detail {
          display: flex;
          align-items: flex-start;
          gap: 16px;
          padding: 16px;
          background: hsl(var(--card));
          border: 1px solid hsl(var(--border));
          border-radius: 8px;
          transition: all 0.2s;
          
          &:hover {
            border-color: hsl(var(--primary) / 0.3);
            background: hsl(var(--muted) / 0.3);
          }
          
          .tech-icon {
            width: 40px;
            height: 40px;
            display: flex;
            align-items: center;
            justify-content: center;
            background: hsl(var(--primary) / 0.1);
            border-radius: 8px;
            flex-shrink: 0;
            
            .el-icon {
              font-size: 24px;
              color: hsl(var(--primary));
            }
          }
          
          .tech-info {
            flex: 1;
            
            .tech-name {
              font-size: 15px;
              font-weight: 500;
              color: hsl(var(--foreground));
              margin-bottom: 4px;
            }
            
            .tech-category {
              font-size: 13px;
              color: hsl(var(--muted-foreground));
            }
          }
        }
      }
      
      .changelog-list {
        display: flex;
        flex-direction: column;
        gap: 16px;
        
        .changelog-item {
          padding: 16px;
          background: hsl(var(--card));
          border: 1px solid hsl(var(--border));
          border-radius: 8px;
          
          .changelog-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
            
            .changelog-time {
              font-size: 13px;
              color: hsl(var(--muted-foreground));
            }
          }
          
          .changelog-changes {
            display: flex;
            flex-direction: column;
            gap: 8px;
            
            .change-item {
              display: flex;
              align-items: center;
              gap: 8px;
              font-size: 13px;
              
              .change-field {
                font-weight: 500;
                color: hsl(var(--foreground));
                min-width: 100px;
              }
              
              .change-old {
                color: hsl(var(--muted-foreground));
                text-decoration: line-through;
              }
              
              .change-arrow {
                color: hsl(var(--muted-foreground));
              }
              
              .change-new {
                color: hsl(var(--primary));
                font-weight: 500;
              }
            }
          }
        }
      }
      
      .empty-state {
        text-align: center;
        padding: 48px 0;
        color: hsl(var(--muted-foreground));
        font-style: italic;
      }
      
      // Directory scans table styles
      .path-link {
        color: hsl(var(--primary));
        text-decoration: none;
        word-break: break-all;
        
        &:hover {
          text-decoration: underline;
        }
      }
      
      .dir-scans-pagination,
      .vuln-scans-pagination {
        margin-top: 16px;
        display: flex;
        justify-content: center;
      }
    }
  }
}

// 图片预览样式
.screenshot-preview-overlay {
  position: fixed;
  z-index: 9999;
  pointer-events: none;
  max-width: 90vw;
  
  .preview-container {
    background: hsl(var(--card));
    border: 2px solid hsl(var(--primary));
    border-radius: 8px;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
    overflow: hidden;
    width: 100%;
    height: 100%;
    
    .preview-image {
      width: 100%;
      height: 100%;
      object-fit: contain;
      display: block;
    }
  }
}

// 预览动画
.preview-fade-enter-active,
.preview-fade-leave-active {
  transition: opacity 0.2s ease;
}

.preview-fade-enter-from,
.preview-fade-leave-to {
  opacity: 0;
}
</style>

