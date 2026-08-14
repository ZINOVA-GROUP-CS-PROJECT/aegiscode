export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export type Database = {
  // Allows to automatically instantiate createClient with right options
  // instead of createClient<Database, { PostgrestVersion: 'XX' }>(URL, KEY)
  __InternalSupabase: {
    PostgrestVersion: "14.15"
  }
  public: {
    Tables: {
      binary_analyses: {
        Row: {
          architecture: string | null
          behavior: Json
          behavioral_diff: Json
          binary_name: string
          created_at: string
          format: string | null
          functions: Json
          id: string
          imports: Json
          integrity_mismatches: Json
          scan_id: string
          sha256: string | null
          strings: Json
          summary: Json
          suspicious_apis: Json
          user_id: string
        }
        Insert: {
          architecture?: string | null
          behavior?: Json
          behavioral_diff?: Json
          binary_name: string
          created_at?: string
          format?: string | null
          functions?: Json
          id?: string
          imports?: Json
          integrity_mismatches?: Json
          scan_id: string
          sha256?: string | null
          strings?: Json
          summary?: Json
          suspicious_apis?: Json
          user_id?: string
        }
        Update: {
          architecture?: string | null
          behavior?: Json
          behavioral_diff?: Json
          binary_name?: string
          created_at?: string
          format?: string | null
          functions?: Json
          id?: string
          imports?: Json
          integrity_mismatches?: Json
          scan_id?: string
          sha256?: string | null
          strings?: Json
          summary?: Json
          suspicious_apis?: Json
          user_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "binary_analyses_scan_id_fkey"
            columns: ["scan_id"]
            isOneToOne: false
            referencedRelation: "scans"
            referencedColumns: ["id"]
          },
        ]
      }
      dependencies: {
        Row: {
          behavioral_fingerprint: Json
          blast_radius: Json
          created_at: string
          direct: boolean
          ecosystem: string | null
          id: string
          license: string | null
          name: string
          poisoning_indicators: Json
          reachability: string
          risk_level: string
          sbom_entry: Json
          scan_id: string
          user_id: string
          version: string | null
          vulnerabilities: Json
        }
        Insert: {
          behavioral_fingerprint?: Json
          blast_radius?: Json
          created_at?: string
          direct?: boolean
          ecosystem?: string | null
          id?: string
          license?: string | null
          name: string
          poisoning_indicators?: Json
          reachability?: string
          risk_level?: string
          sbom_entry?: Json
          scan_id: string
          user_id?: string
          version?: string | null
          vulnerabilities?: Json
        }
        Update: {
          behavioral_fingerprint?: Json
          blast_radius?: Json
          created_at?: string
          direct?: boolean
          ecosystem?: string | null
          id?: string
          license?: string | null
          name?: string
          poisoning_indicators?: Json
          reachability?: string
          risk_level?: string
          sbom_entry?: Json
          scan_id?: string
          user_id?: string
          version?: string | null
          vulnerabilities?: Json
        }
        Relationships: [
          {
            foreignKeyName: "dependencies_scan_id_fkey"
            columns: ["scan_id"]
            isOneToOne: false
            referencedRelation: "scans"
            referencedColumns: ["id"]
          },
        ]
      }
      drift_records: {
        Row: {
          after_state: Json
          before_state: Json
          created_at: string
          description: string
          drift_type: string
          id: string
          scan_id: string | null
          security_impact: string | null
          severity: string
          user_id: string
        }
        Insert: {
          after_state?: Json
          before_state?: Json
          created_at?: string
          description: string
          drift_type: string
          id?: string
          scan_id?: string | null
          security_impact?: string | null
          severity?: string
          user_id?: string
        }
        Update: {
          after_state?: Json
          before_state?: Json
          created_at?: string
          description?: string
          drift_type?: string
          id?: string
          scan_id?: string | null
          security_impact?: string | null
          severity?: string
          user_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "drift_records_scan_id_fkey"
            columns: ["scan_id"]
            isOneToOne: false
            referencedRelation: "scans"
            referencedColumns: ["id"]
          },
        ]
      }
      findings: {
        Row: {
          attack_paths: Json
          created_at: string
          cvss_score: number | null
          cvss_vector: string | null
          cwe: string | null
          cwe_url: string | null
          data_flow: Json
          description: string | null
          epss_percentile: number | null
          epss_score: number | null
          evidence: Json
          evidence_chain: Json
          exploit_confidence: number | null
          exploitability: string
          file_path: string | null
          id: string
          in_kev: boolean
          line_end: number | null
          line_start: number | null
          location: string | null
          reachability: string
          remediation: string | null
          scan_id: string
          secure_fix: string | null
          severity: string
          status: string
          title: string
          updated_at: string
          user_id: string
          verdict: Json
          verified_gone: boolean | null
        }
        Insert: {
          attack_paths?: Json
          created_at?: string
          cvss_score?: number | null
          cvss_vector?: string | null
          cwe?: string | null
          cwe_url?: string | null
          data_flow?: Json
          description?: string | null
          epss_percentile?: number | null
          epss_score?: number | null
          evidence?: Json
          evidence_chain?: Json
          exploit_confidence?: number | null
          exploitability?: string
          file_path?: string | null
          id?: string
          in_kev?: boolean
          line_end?: number | null
          line_start?: number | null
          location?: string | null
          reachability?: string
          remediation?: string | null
          scan_id: string
          secure_fix?: string | null
          severity?: string
          status?: string
          title: string
          updated_at?: string
          user_id?: string
          verdict?: Json
          verified_gone?: boolean | null
        }
        Update: {
          attack_paths?: Json
          created_at?: string
          cvss_score?: number | null
          cvss_vector?: string | null
          cwe?: string | null
          cwe_url?: string | null
          data_flow?: Json
          description?: string | null
          epss_percentile?: number | null
          epss_score?: number | null
          evidence?: Json
          evidence_chain?: Json
          exploit_confidence?: number | null
          exploitability?: string
          file_path?: string | null
          id?: string
          in_kev?: boolean
          line_end?: number | null
          line_start?: number | null
          location?: string | null
          reachability?: string
          remediation?: string | null
          scan_id?: string
          secure_fix?: string | null
          severity?: string
          status?: string
          title?: string
          updated_at?: string
          user_id?: string
          verdict?: Json
          verified_gone?: boolean | null
        }
        Relationships: [
          {
            foreignKeyName: "findings_scan_id_fkey"
            columns: ["scan_id"]
            isOneToOne: false
            referencedRelation: "scans"
            referencedColumns: ["id"]
          },
        ]
      }
      remediations: {
        Row: {
          created_at: string
          finding_id: string
          fix_code: string | null
          fix_description: string | null
          id: string
          model: string
          updated_at: string
          user_id: string
          verification_result: Json
          verification_status: string
        }
        Insert: {
          created_at?: string
          finding_id: string
          fix_code?: string | null
          fix_description?: string | null
          id?: string
          model?: string
          updated_at?: string
          user_id?: string
          verification_result?: Json
          verification_status?: string
        }
        Update: {
          created_at?: string
          finding_id?: string
          fix_code?: string | null
          fix_description?: string | null
          id?: string
          model?: string
          updated_at?: string
          user_id?: string
          verification_result?: Json
          verification_status?: string
        }
        Relationships: [
          {
            foreignKeyName: "remediations_finding_id_fkey"
            columns: ["finding_id"]
            isOneToOne: false
            referencedRelation: "findings"
            referencedColumns: ["id"]
          },
        ]
      }
      reports: {
        Row: {
          content: Json
          created_at: string
          format: string
          id: string
          scan_ids: Json
          summary: Json
          title: string
          user_id: string
        }
        Insert: {
          content?: Json
          created_at?: string
          format?: string
          id?: string
          scan_ids?: Json
          summary?: Json
          title?: string
          user_id?: string
        }
        Update: {
          content?: Json
          created_at?: string
          format?: string
          id?: string
          scan_ids?: Json
          summary?: Json
          title?: string
          user_id?: string
        }
        Relationships: []
      }
      scans: {
        Row: {
          created_at: string
          id: string
          input_hash: string | null
          language: string | null
          loc: number | null
          model: string
          name: string
          scan_type: string
          status: string
          summary: Json
          updated_at: string
          user_id: string
        }
        Insert: {
          created_at?: string
          id?: string
          input_hash?: string | null
          language?: string | null
          loc?: number | null
          model?: string
          name?: string
          scan_type: string
          status?: string
          summary?: Json
          updated_at?: string
          user_id?: string
        }
        Update: {
          created_at?: string
          id?: string
          input_hash?: string | null
          language?: string | null
          loc?: number | null
          model?: string
          name?: string
          scan_type?: string
          status?: string
          summary?: Json
          updated_at?: string
          user_id?: string
        }
        Relationships: []
      }
      threat_intel: {
        Row: {
          created_at: string
          cve: string | null
          cvss_score: number | null
          description: string | null
          epss_percentile: number | null
          epss_score: number | null
          finding_id: string | null
          id: string
          in_kev: boolean
          intel_references: Json
          kev_date: string | null
          raw: Json
          source: string
          user_id: string
        }
        Insert: {
          created_at?: string
          cve?: string | null
          cvss_score?: number | null
          description?: string | null
          epss_percentile?: number | null
          epss_score?: number | null
          finding_id?: string | null
          id?: string
          in_kev?: boolean
          intel_references?: Json
          kev_date?: string | null
          raw?: Json
          source?: string
          user_id?: string
        }
        Update: {
          created_at?: string
          cve?: string | null
          cvss_score?: number | null
          description?: string | null
          epss_percentile?: number | null
          epss_score?: number | null
          finding_id?: string | null
          id?: string
          in_kev?: boolean
          intel_references?: Json
          kev_date?: string | null
          raw?: Json
          source?: string
          user_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "threat_intel_finding_id_fkey"
            columns: ["finding_id"]
            isOneToOne: false
            referencedRelation: "findings"
            referencedColumns: ["id"]
          },
        ]
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      [_ in never]: never
    }
    Enums: {
      [_ in never]: never
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] &
        DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] &
        DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R
      }
      ? R
      : never
    : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I
      }
      ? I
      : never
    : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U
      }
      ? U
      : never
    : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    | keyof DefaultSchema["Enums"]
    | { schema: keyof DatabaseWithoutInternals },
  EnumName extends DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never = never,
> = DefaultSchemaEnumNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never

export const Constants = {
  public: {
    Enums: {},
  },
} as const
