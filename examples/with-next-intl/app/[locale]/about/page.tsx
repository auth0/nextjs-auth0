import { Link } from "@/src/i18n/routing"
import { useTranslations } from "next-intl"

export default function AboutPage() {
  const t = useTranslations("AboutPage")

  return (
    <div>
      <h1>{t("title")}</h1>
      <Link href="/">{t("home")}</Link>
    </div>
  )
}
